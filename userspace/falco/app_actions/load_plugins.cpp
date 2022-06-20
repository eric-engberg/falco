/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "application.h"
#include <plugin_manager.h>

using namespace falco::app;

// todo(XXX): this is complicated. I think this needs to be split in multiple parts
// 1) load plugins and get all the event sources and add them to the engine
// 2) create one inspector for each event source and attach all the compatible
//    extractors to it
// 3) not sure when to create all the filtercheck lists, maybe during step 2)
//
// issue: for scap files, the source index is dictated by the inspector, whereas
//        for live mode the source index is dictated by Falco (need to match it against the engine idx)
//           -> there should be a mapping engine src idx -> inspector idx

// plan:
// 1) load all plugins, populate the event source list and the list of compatible (DONE)
//    extraction plugin for each source (throw errors and stuff).
//    populate list of std::vector<falco_engine::plugin_version_requirement> (maybe bundle them in a struct containing also the compatible extract sources)
// 2) select/enable/disable event sources (DONE)
// 3) init inspectors: Create inspectors(1 for capture mode, N for live mode) and cofig them.
//                     Populate list of filterchecks for each event source (decide which inspector retain them)
//					   Perform source extraction compat checks (DONE)
// 4) init_engine: add filtercheck lists for each source
// 5) list fields: (DONE)
// 6) ... -> validate sources: use the pre-populated list of :plugin_version_requirement
// 7) ... -> open inspectors: 1 for capture mode, N for live mode
// 8) process_events: spawn a thread for each open inspector. Use main thread if capture mode or just 1 live source.
//                    get rid of close_inspector action, close each inspector in thread and join with all threads (if any).
// 9) ... -> done
application::run_result application::load_plugins()
{
#ifdef MUSL_OPTIMIZED
	if (!m_state->config->m_plugins.empty())
	{
		return run_result::fatal("Can not load/use plugins with musl optimized build");
	}
#endif

	// Initialize set of enabled event source. 
	// By default, the set includes the 'syscall' event source
	m_state->enabled_sources = {falco_common::syscall_source};

	// Initialize the offline inspector. This is used to load all the configured
	// plugins in order to have them available everytime we need to access
	// their static info. If Falco is in capture mode, this inspector is also
	// used to open and read the trace file
	m_state->offline_inspector.reset(new sinsp());

	// Load all the configured plugins in the offline inspector
	for(auto &p : m_state->config->m_plugins)
	{
		falco_logger::log(LOG_INFO, "Loading plugin (" + p.m_name + ") from file " + p.m_library_path + "\n");

		// Load the plugin without initializing it
		auto plugin = m_state->offline_inspector->register_plugin(p.m_library_path);

		// If the plugin supports event sourcing capability, add it to the set
		// of enabled event sources
		if(plugin->caps() & CAP_SOURCING)
		{
			m_state->enabled_sources.insert(plugin->event_source());
		}
	}

	return run_result::ok();
}
