// SPDX-FileCopyrightText: 2017 javierptd <javierptd@gmail.com>
// SPDX-FileCopyrightText: 2025 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef INCLUDE_HEAP_JEMALLOC_STD_C
#define INCLUDE_HEAP_JEMALLOC_STD_C
#include "rz_util/rz_log.h"
#define HEAP32 1
#include "linux_heap_jemalloc.c"
#undef HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX
#undef PFMTx

#if HEAP32
#define GH(x)   x##_32
#define GHT     ut32
#define GHT_MAX UT32_MAX
#define PFMTx   PFMT32x
#else
#define GH(x)   x##_64
#define GHT     ut64
#define GHT_MAX UT64_MAX
#define PFMTx   PFMT64x
#endif

static GHT GH(je_get_va_symbol)(RzCore *core, const char *path, const char *sym_name) {
	GHT vaddr = GHT_MAX;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	void **iter;
	RzBinSymbol *s;

	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.obj_opts.elf_load_sections = rz_config_get_b(core->config, "elf.load.sections");
	opt.obj_opts.elf_checks_sections = rz_config_get_b(core->config, "elf.checks.sections");
	opt.obj_opts.elf_checks_segments = rz_config_get_b(core->config, "elf.checks.segments");

	RzBinFile *libc_bf = rz_bin_open(bin, path, &opt);
	if (!libc_bf) {
		return vaddr;
	}

	RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *syms = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	rz_pvector_foreach (syms, iter) {
		s = *iter;
		if (!strcmp(s->name, sym_name)) {
			vaddr = s->vaddr;
			break;
		}
	}

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
	return vaddr;
}


static bool GH(rz_resolve_jemalloc)(RzCore *core, char *symname, ut64 *symbol) {
	RzListIter *iter;
	RzDebugMap *map;
	const char *jemalloc_path = NULL;
	ut64 jemalloc_addr = UT64_MAX;
	const char *binary_path = NULL;
	ut64 binary_addr = UT64_MAX;

	if (!core || !core->dbg || !core->dbg->maps) {
		return false;
	}
	rz_debug_map_sync(core->dbg);

	rz_list_foreach (core->dbg->maps, iter, map) {
		if (strstr(map->name, "libjemalloc.")) {
			jemalloc_addr = map->addr;
			jemalloc_path = map->name;
			break;
		}
		if (binary_path == NULL && map->perm & RZ_PERM_X) {
			/* Skip common library patterns */
			if (!strstr(map->name, ".so") && !strstr(map->name, "lib") &&
			    !strstr(map->name, "[") && strlen(map->name) > 0) {
				binary_addr = map->addr;
				binary_path = map->name;
			}
		}
	}

	/* Try dynamic library first */
	if (jemalloc_path) {
		char *path = rz_str_newf("%s", jemalloc_path);
		if (rz_file_exists(path)) {
			GHT vaddr = GH(je_get_va_symbol)(core, path, symname);
			if (jemalloc_addr != GHT_MAX && vaddr != GHT_MAX) {
				*symbol = jemalloc_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}

	/* Fall back to static linking */
	if (binary_path) {
		char *path = rz_str_newf("%s", binary_path);
		if (rz_file_exists(path)) {
			GHT vaddr = GH(je_get_va_symbol)(core, path, symname);
			if (binary_addr != GHT_MAX && vaddr != GHT_MAX) {
				*symbol = binary_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}
	return false;
}

/**
 * \brief Detect jemalloc version by checking for version-specific symbols
 *
 * jemalloc 4.x has je_chunksize symbol (chunk-based architecture)
 * jemalloc 5.x does NOT have je_chunksize (extent-based architecture)
 */
static bool GH(rz_jemalloc_detect_version)(RzCore *core) {
	ut64 chunksize_addr;
	const char *current_version = rz_config_get(core->config, "dbg.jemalloc.version");

	// Try to resolve je_chunksize - only exists in jemalloc 4.5.0
	if (GH(rz_resolve_jemalloc)(core, "je_chunksize", &chunksize_addr)) {
		// je_chunksize found -> jemalloc 4.5.0
		if (strcmp(current_version, "4.5.0") != 0) {
			rz_config_set(core->config, "dbg.jemalloc.version", "4.5.0");
			RZ_LOG_INFO("Detected jemalloc 4.5.0 (je_chunksize symbol found)\n");
		}
		return true;
	} else if (GH(rz_resolve_jemalloc)(core, "je_arena_emap_global", &chunksize_addr)) {
		if (strcmp(current_version, "5.3.0") != 0) {
			rz_config_set(core->config, "dbg.jemalloc.version", "5.3.0");
			RZ_LOG_INFO("Detected jemalloc 5.3.0 (je_arena_emap_global symbol found)\n");
		}
		return true;
	} else {
		rz_config_set(core->config, "dbg.jemalloc.version", "NULL");
		RZ_LOG_WARN("jemalloc version cannot be determined\n");
		return false;
	}
}

static void GH(jemalloc_get_chunks_450)(RzCore *core, const char *input) {
	ut64 cnksz;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!GH(rz_resolve_jemalloc)(core, "je_chunksize", &cnksz)) {
		RZ_LOG_ERROR("Fail at reading symbol je_chunksize\n");
		return;
	}
	rz_io_read_at(core->io, cnksz, (ut8 *)&cnksz, sizeof(GHT));

	if (input[0] == '\0') {
		RZ_LOG_ERROR("need an arena_t_450 to associate chunks\n");
	} else if (input[0] != '*') {
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		GHT arena = GHT_MAX;
		arena_t_450 *ar = RZ_NEW0(arena_t_450);
		extent_node_t_450 *node = RZ_NEW0(extent_node_t_450), *head = RZ_NEW0(extent_node_t_450);
		arena = rz_num_math(core->num, addr_str);

		if (arena) {
			rz_io_read_at(core->io, arena, (ut8 *)ar, sizeof(arena_t_450));
			rz_io_read_at(core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof(extent_node_t_450));
			if (head->en_addr) {
				PRINT_YA("   Chunk - start: ");
				PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)head->en_addr);
				PRINT_YA(", end: ");
				PRINTF_BA("0x%08" PFMT64x, (ut64)head->en_addr + cnksz);
				PRINT_YA(", size: ");
				PRINTF_BA("0x%08" PFMT64x "\n", (ut64)cnksz);
				rz_io_read_at(core->io, (ut64)(size_t)head->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t_450));
				while (node && node->en_addr != head->en_addr) {
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)node->en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, (ut64)node->en_addr + cnksz);
					PRINT_YA(", size: ");
					PRINTF_BA("0x%08" PFMT64x "\n", cnksz);
					rz_io_read_at(core->io, (ut64)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t_450));
				}
			}
		}
		free(ar);
		free(head);
		free(node);
	} else if (input[0] == '*') {
		int i = 0;
		ut64 sym;
		GHT arenas = GHT_MAX, arena = GHT_MAX;
		arena_t_450 *ar = RZ_NEW0(arena_t_450);
		extent_node_t_450 *node = RZ_NEW0(extent_node_t_450);
		extent_node_t_450 *head = RZ_NEW0(extent_node_t_450);

		if (!node || !head) {
			RZ_LOG_ERROR("Failed to allocate extent_node_t_450\n");
			free(ar);
			free(node);
			free(head);
			return;
		}

		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &sym)) {
			rz_io_read_at(core->io, sym, (ut8 *)&arenas, sizeof(GHT));
			for (;;) {
				rz_io_read_at(core->io, arenas + i * sizeof(GHT), (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					break;
				}
				PRINTF_GA("arenas[%d]: @ 0x%" PFMTx " { \n", i++, (GHT)arena);
				rz_io_read_at(core->io, arena, (ut8 *)ar, sizeof(arena_t_450));
				rz_io_read_at(core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof(extent_node_t_450));
				if (head->en_addr != 0) {
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)head->en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, (ut64)head->en_addr + cnksz);
					PRINT_YA(", size: ");
					PRINTF_BA("0x%08" PFMT64x "\n", (ut64)cnksz);
					ut64 addr = (ut64)(size_t)head->ql_link.qre_next;
					rz_io_read_at(core->io, addr, (ut8 *)node, sizeof(extent_node_t_450));
					while (node && head && node->en_addr != head->en_addr) {
						PRINT_YA("   Chunk - start: ");
						PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)node->en_addr);
						PRINT_YA(", end: ");
						PRINTF_BA("0x%" PFMT64x, (ut64)node->en_addr + cnksz);
						PRINT_YA(", size: ");
						PRINTF_BA("0x%" PFMT64x "\n", cnksz);
						rz_io_read_at(core->io, (GHT)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t_450));
					}
				}
				PRINT_GA("}\n");
			}
		}
		free(ar);
		free(head);
		free(node);
	}
}

static void GH(jemalloc_print_narenas_450)(RzCore *core, const char *input) {
	ut64 symaddr;
	ut64 arenas;
	GHT arena = GHT_MAX;
	arena_t_450 *ar = RZ_NEW0(arena_t_450);
	if (!ar) {
		return;
	}
	GH(arena_stats_t_450) *stats = RZ_NEW0(GH(arena_stats_t_450));
	if (!stats) {
		free(ar);
		return;
	}
	int i = 0;
	GHT narenas = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (input[0] == '\0') {
		if (GH(rz_resolve_jemalloc)(core, "narenas_total", &symaddr)) {
			rz_io_read_at(core->io, symaddr, (ut8 *)&narenas, sizeof(GHT));
			PRINTF_GA("narenas : %" PFMT64d "\n", (ut64)narenas);
		}
		if (narenas == 0) {
			RZ_LOG_ERROR("No arenas allocated.\n");
			free(stats);
			free(ar);
			return;
		}
		if (narenas == GHT_MAX) {
			RZ_LOG_ERROR("Cannot find narenas_total\n");
			free(stats);
			free(ar);
			return;
		}

		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			rz_io_read_at(core->io, arenas, (ut8 *)&arenas, sizeof(GHT));
			PRINTF_GA("arenas[%" PFMT64d "] @ 0x%" PFMT64x " {\n", (ut64)narenas, (ut64)arenas);
			for (i = 0; i < narenas; i++) {
				ut64 at = arenas + (i * sizeof(GHT));
				rz_io_read_at(core->io, at, (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					PRINTF_YA("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA("  arenas[%d]: ", i);
				PRINTF_BA("@ 0x%" PFMT64x "\n", (ut64)arena);
			}
		}
		PRINT_GA("}\n");
	} else {
		// Handle address argument (with or without leading space)
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		arena = rz_num_math(core->num, addr_str);
		rz_io_read_at(core->io, (GHT)arena, (ut8 *)ar, sizeof(arena_t_450));
		PRINT_GA("struct arena_s {\n");
#define OO(x) (ut64)(arena + rz_offsetof(arena_t_450, x))
		PRINTF_BA("  ind = 0x%x\n", ar->ind);
		PRINTF_BA("  nthreads: application allocation = 0x%" PFMT64x "\n", (ut64)ar->nthreads[0]);
		PRINTF_BA("  nthreads: internal metadata allocation = 0x%" PFMT64x "\n", (ut64)ar->nthreads[1]);
		PRINTF_BA("  lock = 0x%" PFMT64x "\n", OO(lock));
		PRINTF_BA("  stats = 0x%" PFMT64x "\n", OO(stats));
		PRINTF_BA("  tcache_ql = 0x%" PFMT64x "\n", OO(tcache_ql));
		PRINTF_BA("  prof_accumbytes = 0x%" PFMT64x "x\n", (ut64)ar->prof_accumbytes);
		PRINTF_BA("  offset_state = 0x%" PFMT64x "\n", (ut64)ar->offset_state);
		PRINTF_BA("  dss_prec_t = 0x%" PFMT64x "\n", OO(dss_prec));
		PRINTF_BA("  achunks = 0x%" PFMT64x "\n", OO(achunks));
		PRINTF_BA("  extent_sn_next = 0x%" PFMT64x "\n", (ut64)(size_t)ar->extent_sn_next);
		PRINTF_BA("  spare = 0x%" PFMT64x "\n", (ut64)(size_t)ar->spare);
		PRINTF_BA("  lg_dirty_mult = 0x%" PFMT64x "\n", (ut64)(ssize_t)ar->lg_dirty_mult);
		PRINTF_BA("  purging = %s\n", rz_str_bool(ar->purging));
		PRINTF_BA("  nactive = 0x%" PFMT64x "\n", (ut64)(size_t)ar->nactive);
		PRINTF_BA("  ndirty = 0x%" PFMT64x "\n", (ut64)(size_t)ar->ndirty);

		PRINTF_BA("  runs_dirty = 0x%" PFMT64x "\n", OO(runs_dirty));
		PRINTF_BA("  chunks_cache = 0x%" PFMT64x "\n", OO(chunks_cache));
		PRINTF_BA("  huge = 0x%" PFMT64x "\n", OO(huge));
		PRINTF_BA("  huge_mtx = 0x%" PFMT64x "\n", OO(huge_mtx));

		PRINTF_BA("  chunks_szsnad_cached = 0x%" PFMT64x "\n", OO(chunks_szsnad_cached));
		PRINTF_BA("  chunks_ad_cached = 0x%" PFMT64x "\n", OO(chunks_ad_cached));
		PRINTF_BA("  chunks_szsnad_retained = 0x%" PFMT64x "\n", OO(chunks_szsnad_retained));
		PRINTF_BA("  chunks_ad_cached = 0x%" PFMT64x "\n", OO(chunks_ad_retained));

		PRINTF_BA("  chunks_mtx = 0x%" PFMT64x "\n", OO(chunks_mtx));
		PRINTF_BA("  node_cache = 0x%" PFMT64x "\n", OO(node_cache));
		PRINTF_BA("  node_cache_mtx = 0x%" PFMT64x "\n", OO(node_cache_mtx));
		PRINTF_BA("  chunks_hooks = 0x%" PFMT64x "\n", OO(chunk_hooks));
		PRINTF_BA("  bins = %d 0x%" PFMT64x "\n", JM_NBINS, OO(bins));
		PRINTF_BA("  runs_avail = %d 0x%" PFMT64x "\n", GH(NPSIZES), OO(runs_avail));
		PRINT_GA("}\n");
	}
	free(ar);
	free(stats);
}

// Helper to print bin info for a single arena
static void GH(jemalloc_print_arena_bins_450)(RzCore *core, GHT arena, ut64 bin_info, RzConsPrintablePalette *pal) {
	int j;
	arena_t_450 *ar = RZ_NEW0(arena_t_450);
	arena_bin_info_t_450 *b = RZ_NEW0(arena_bin_info_t_450);
	if (!ar || !b) {
		free(ar);
		free(b);
		return;
	}

	rz_io_read_at(core->io, arena, (ut8 *)ar, sizeof(arena_t_450));
	for (j = 0; j < JM_NBINS; j++) {
		rz_io_read_at(core->io, (GHT)(bin_info + j * sizeof(arena_bin_info_t_450)),
			(ut8 *)b, sizeof(arena_bin_info_t_450));
		PRINT_YA("    {\n");
		PRINT_YA("       regsize : ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->reg_size);
		PRINT_YA("       redzone size ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->redzone_size);
		PRINT_YA("       reg_interval : ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->reg_interval);
		PRINT_YA("       run_size : ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->run_size);
		PRINT_YA("       nregs : ");
		PRINTF_BA("0x%x\n", b->nregs);
		PRINT_YA("       reg0_offset : ");
		PRINTF_BA("0x%" PFMT64x "\n\n", (ut64)b->reg0_offset);
		PRINT_YA("    }\n");
	}
	free(ar);
	free(b);
}

static void GH(jemalloc_get_bins_450)(RzCore *core, const char *input) {
	int i = 0;
	ut64 bin_info;
	ut64 arenas;
	GHT arena = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (input[0] == '\0') {
		// No argument - use symbol resolution (debug mode)
		if (!GH(rz_resolve_jemalloc)(core, "je_arena_bin_info", &bin_info)) {
			RZ_LOG_ERROR("Cannot resolve je_arena_bin_info\n");
			return;
		}
		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			rz_io_read_at(core->io, arenas, (ut8 *)&arenas, sizeof(GHT));
			PRINTF_GA("arenas @ 0x%" PFMTx " {\n", (GHT)arenas);
			for (;;) {
				rz_io_read_at(core->io, arenas + i * sizeof(GHT), (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					break;
				}
				PRINTF_YA("  arenas[%d]: @ 0x%" PFMTx " {\n", i++, (GHT)arena);
				GH(jemalloc_print_arena_bins_450)(core, arena, bin_info, pal);
				PRINT_YA("  }\n");
			}
		}
		PRINT_GA("}\n");
	} else {
		// Static mode - requires two arguments: dmxb <arena_addr> <bin_info_addr>
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;

		char *args = strdup(addr_str);
		char *bin_info_str = strchr(args, ' ');

		if (!bin_info_str) {
			RZ_LOG_ERROR("Usage: dmxb <arena_addr> <bin_info_addr>\n");
			free(args);
			return;
		}

		*bin_info_str++ = '\0';
		arena = rz_num_math(core->num, args);
		bin_info = rz_num_math(core->num, bin_info_str);

		PRINTF_GA("arena_t @ 0x%" PFMT64x " bins[%d] {\n", (ut64)arena, JM_NBINS);
		GH(jemalloc_print_arena_bins_450)(core, arena, bin_info, pal);
		PRINT_GA("}\n");

		free(args);
	}
}

static void GH(jemalloc_find_extent_530)(RzCore *core, const char *input) {
	RZ_LOG_WARN("dmxe 530\n");
	return;
}

static void GH(jemalloc_extent_info_530)(RzCore *core, const char *input) {
	RZ_LOG_WARN("dmxei 530\n");
	return;
}

static void GH(jemalloc_get_bins_530)(RzCore *core, const char *input) {
	RZ_LOG_WARN("dmxb 530\n");
	return;	
}

static void GH(jemalloc_print_narenas_530)(RzCore *core, const char *input) {
	RZ_LOG_WARN("dmxa 530\n");
	return;
	
}



static void GH(cmd_dbg_map_jemalloc)(RzCore *core, char dmx_variant, const char *arg) {
	// Auto-detect jemalloc version if in debug mode (no args = symbol resolution needed)
	if (!arg || arg[0] == '\0' || arg[0] == '*') {
		GH(rz_jemalloc_detect_version)(core);
	}

	const char *version = rz_config_get(core->config, "dbg.jemalloc.version");
	if (version && strcmp(version, "4.5.0") == 0) {
		switch (dmx_variant) {
		case 'a': // dmxa
			GH(jemalloc_print_narenas_450)(core, arg);
			break;
		case 'b': // dmxb
			GH(jemalloc_get_bins_450)(core, arg);
			break;
		case 'c': // dmxc
			GH(jemalloc_get_chunks_450)(core, arg);
			break;
		}
	} 
	else if (version && strcmp(version, "5.3.0") == 0) {
		switch (dmx_variant) {
		case 'a': // dmxa - print arena
			GH(jemalloc_print_narenas_530)(core, arg);
			break;
		case 'b': // dmxb - bin info
			GH(jemalloc_get_bins_530)(core, arg);
			break;
		case 'e': // dmxe - find extent for malloc'd address
			GH(jemalloc_find_extent_530)(core, arg);
			break;
		case 'i': // dmxei - extent info
			GH(jemalloc_extent_info_530)(core, arg);
			break;
		}
	} else {
		RZ_LOG_ERROR("Unknown jemalloc version. Please set dbg.jemalloc.version to '4.5.0' or '5.3.0'\n");
	}
}
