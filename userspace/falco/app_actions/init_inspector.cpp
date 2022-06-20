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

static void init_syscall_inspector(std::shared_ptr<sinsp> inspector, const falco::app::cmdline_options& opts)
{
	inspector->set_buffer_format(opts.event_buffer_format);

	// If required, set the CRI paths
	for (auto &p : opts.cri_socket_paths)
	{
		if (!p.empty())
		{
			inspector->add_cri_socket_path(p);
		}
	}

	// Decide whether to do sync or async for CRI metadata fetch
	inspector->set_cri_async(!opts.disable_cri_async);

	//
	// If required, set the snaplen
	//
	if(opts.snaplen != 0)
	{
		inspector->set_snaplen(opts.snaplen);
	}

	if(!opts.all_events)
	{
		// Drop EF_DROP_SIMPLE_CONS kernel side
		inspector->set_simple_consumer();
		// Eventually, drop any EF_DROP_SIMPLE_CONS event
		// that reached userspace (there are some events that are not syscall-based
		// like signaldeliver, that have the EF_DROP_SIMPLE_CONS flag)
		inspector->set_drop_event_flags(EF_DROP_SIMPLE_CONS);
	}

	inspector->set_hostname_and_port_resolution_mode(false);
}

static bool populate_filterchecks(
	std::shared_ptr<sinsp> inspector,
	const std::string& source,
	filter_check_list& filterchecks,
	std::set<std::string>& used_plugin_names,
	std::string& err)
{
	std::vector<const filter_check_info*> info;
	for(const auto& p : inspector->get_plugin_manager()->plugins())
	{
		if (!(p->caps() & CAP_EXTRACTION))
		{
			continue;
		}

		// check if some fields are overlapping on this event sources
		info.clear();
		filterchecks.get_all_fields(info);
		for (auto &info : info)
		{
			for (int32_t i = 0; i < info->m_nfields; i++)
			{
				// check if one of the fields extractable by the plugin
				// is already provided by another filtercheck for this source
				std::string fname = info->m_fields[i].m_name;
				for (auto &f : p->fields())
				{
					if (std::string(f.m_name) == fname)
					{
						err = "Plugin '" + p->name()
							+ "' supports extraction of field '" + fname
							+ "' that is overlapping for source '" + source + "'";
						return false;
					}
				}
			}
		}

		// add plugin filterchecks to the event source
		filterchecks.add_filter_check(sinsp_plugin::new_filtercheck(p));
		used_plugin_names.insert(p->name());
	}
	return true;
}

// todo: rename this to init_inspectors()
application::run_result application::init_inspector()
{
	std::string err;
	std::set<std::string> used;
	auto& all_plugins = m_state->offline_inspector->get_plugin_manager()->plugins();
	
	for (const auto &src : m_state->enabled_sources)
	{
		auto& filterchecks = m_state->source_filterchecks[src];
		std::shared_ptr<sinsp> inspector = nullptr;

		// choose an inspector
		if (is_capture_mode())
		{
			// in capture mode, we do everything within the offline inspector
			inspector = m_state->offline_inspector;
		}
		else
		{
			// in live mode, we create a new inspector for this event source
			inspector = std::shared_ptr<sinsp>(new sinsp());
			m_state->live_inspectors.push_back(inspector);
		}
		m_state->source_inspectors[src] = inspector;

		// handle syscall and plugin sources differently
		// todo(jasondellaluce): change this once we support extracting plugin fields from syscalls
		if (src == falco_common::syscall_source)
		{
			init_syscall_inspector(inspector, m_options);
			filterchecks = g_filterlist;
		}
		else
		{
			// load and init all plugins compatible with this inspector
			// (will be all plugins if in capture mode, in which case we just need to init them)
			for (const auto& p : all_plugins)
			{
				auto plugin = p;
				auto& config = get_plugin_config(p->name());
				bool is_input_plugin = p->caps() & CAP_SOURCING && p->event_source() == src;

				// if in live mode, we have to register all the plugins related
				// to this event source
				if (!is_capture_mode())
				{
					plugin = nullptr;
					if (is_input_plugin || (p->caps() & CAP_EXTRACTION && p->is_source_compatible(src)))
					{
						plugin = inspector->register_plugin(config.m_library_path);
						if (is_input_plugin)
						{
							inspector->set_input_plugin(config.m_name, config.m_open_params);
						}
					}
				}

				// if plugin is registered in this inspector (always true in capture mode)
				if (plugin)
				{
					if (!plugin->init(config.m_init_config, err))
					{
						return run_result::fatal(err);
					}
					if (is_input_plugin)
					{
						filterchecks.add_filter_check(inspector->new_generic_filtercheck());
					}
					used.insert(plugin->name());
				}
			}

			// populate filterchecks for this inspector
			if (!populate_filterchecks(inspector, src, filterchecks, used, err))
			{
				return run_result::fatal(err);
			}	
		}
	}

	// check if some plugin with field extraction cap is not used
	for (const auto& p : all_plugins)
	{
		if(p->caps() & CAP_EXTRACTION && used.find(p->name()) == used.end())
		{
			return run_result::fatal("Plugin '" + p->name()
				+ "' has field extraction capability but is not compatible with any enabled event source");
		}
	}

	return run_result::ok();
}
