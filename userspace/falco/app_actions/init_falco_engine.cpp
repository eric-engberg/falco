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

void application::configure_output_format()
{
	std::string output_format;
	bool replace_container_info = false;

	if(m_options.print_additional == "c" || m_options.print_additional == "container")
	{
		output_format = "container=%container.name (id=%container.id)";
		replace_container_info = true;
	}
	else if(m_options.print_additional == "k" || m_options.print_additional == "kubernetes")
	{
		output_format = "k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name container=%container.id";
		replace_container_info = true;
	}
	else if(m_options.print_additional == "m" || m_options.print_additional == "mesos")
	{
		output_format = "task=%mesos.task.name container=%container.id";
		replace_container_info = true;
	}
	else if(!m_options.print_additional.empty())
	{
		output_format = m_options.print_additional;
		replace_container_info = false;
	}

	if(!output_format.empty())
	{
		m_state->engine->set_extra(output_format, replace_container_info);
	}
}

bool application::add_source_to_engine(const std::string& src, std::string& err)
{
	auto &inspector = m_state->source_inspectors[src];

	// Factories that can create filters/formatters for the event source
	// and add it in the engine
	std::shared_ptr<gen_event_filter_factory> filter_factory = nullptr;
	std::shared_ptr<gen_event_formatter_factory> formatter_factory = nullptr;

	if (src == falco_common::syscall_source)
	{
		filter_factory = std::shared_ptr<gen_event_filter_factory>(new sinsp_filter_factory(inspector.get()));
		formatter_factory = std::shared_ptr<gen_event_formatter_factory>(new sinsp_evt_formatter_factory(inspector.get()));
	}
	else
	{
		auto &filterchecks = m_state->source_filterchecks[src];
		filter_factory = std::shared_ptr<gen_event_filter_factory>(new sinsp_filter_factory(inspector.get(), filterchecks));
		formatter_factory = std::shared_ptr<gen_event_formatter_factory>(new sinsp_evt_formatter_factory(inspector.get(), filterchecks));
	}

	if(m_state->config->m_json_output)
	{
		formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}
	m_state->source_engine_idx[src] = m_state->engine->add_source(src, filter_factory, formatter_factory);

	// note: in capture mode, we can assume that the plugin source index will
	// be the same in both the falco engine and the sinsp plugin manager.
	// This assumption stands because the plugin manager stores sources in a
	// vector, and the syscall source is appended in the engine *after* the sources
	// coming from plugins. The reason why this can't work with live mode,
	// is because in that case event sources are scattered across different
	// inspectors. Since this is an implementation-based assumption, we
	// check this and return an error to spot regressions in the future.
	if (is_capture_mode() && src != falco_common::syscall_source)
	{
		for (const auto &p : inspector->get_plugin_manager()->plugins())
		{
			if (p->caps() & CAP_SOURCING)
			{
				bool added = false;
				auto source_idx = inspector->get_plugin_manager()->source_idx_by_plugin_id(p->id(), added);
				if (!added || source_idx != m_state->source_engine_idx[src])
				{
					err = "Could not add event source in the engine: " + p->event_source();
					return false;
				}
			}
		}
	}

	return true;
}

application::run_result application::init_falco_engine()
{
	std::string err;

	// add all non-syscall event sources in engine
	for (const auto& src : m_state->enabled_sources)
	{
		if (src == falco_common::syscall_source)
		{
			// we skip the syscall as we want it to be the one added for last
			// in the engine. This makes the source index assignment easier.
			continue;
		}
		if (!add_source_to_engine(src, err))
		{
			return run_result::fatal(err);
		}
	}

	// add syscall as last source
	if (is_syscall_source_enabled())
	{
		if (!add_source_to_engine(falco_common::syscall_source, err))
		{
			return run_result::fatal(err);
		}
	}

	// setup the rest of the engine config
	configure_output_format();
	m_state->engine->set_min_priority(m_state->config->m_min_priority);

	return run_result::ok();
}
