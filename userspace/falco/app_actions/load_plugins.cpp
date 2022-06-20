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
