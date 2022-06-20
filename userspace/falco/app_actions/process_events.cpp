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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "falco_utils.h"
#include "event_drops.h"
#ifndef MINIMAL_BUILD
#include "webserver.h"
#endif
#include "statsfilewriter.h"
#include "application.h"

#include <plugin_manager.h>

using namespace falco::app;

static void open_inspector(std::shared_ptr<sinsp> inspector, const std::string& source, bool userspace)
{
	if (source == falco_common::syscall_source)
	{
		try
		{
			// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
			//
			// Falco uses a ptrace(2) based userspace implementation.
			// Regardless of the implementation, the underlying method remains the same.
			if(userspace)
			{
				inspector->open_udig();
			}
			else
			{
				inspector->open();
			}
		}
		catch(sinsp_exception &e)
		{
			// If syscall input source is enabled and not through userspace instrumentation
			if (!userspace)
			{
				// Try to insert the Falco kernel module
				if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
				{
					falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
				}
				inspector->open();
				return;
			}
			throw e;
		}
	}
	else
	{
		inspector->open();
	}
}

// todo: pass inspector as parameter
//
// Event processing loop
//
application::run_result application::do_inspect(
	std::shared_ptr<sinsp> inspector,
	const std::string& source,
	syscall_evt_drop_mgr &sdropmgr,
	uint64_t duration_to_tot_ns,
	uint64_t &num_evts)
{
	int32_t rc;
	sinsp_evt* ev;
	StatsFileWriter writer;
	uint64_t duration_start = 0;
	uint32_t timeouts_since_last_success_or_msg = 0;
	std::size_t source_idx = 0;
	bool source_idx_found = false;
	bool is_capture_mode = source.empty();
	bool is_syscall_source = source == falco_common::syscall_source;
	bool syscall_source_idx = m_state->source_engine_idx[falco_common::syscall_source];
	
	if (!is_capture_mode)
	{
		source_idx = m_state->source_engine_idx[source];
	}

	// reset event counter
	num_evts = 0;

	// init drop manager if we are inspecting syscalls
	if (is_syscall_source)
	{
		sdropmgr.init(inspector,
			m_state->outputs,
			m_state->config->m_syscall_evt_drop_actions,
			m_state->config->m_syscall_evt_drop_threshold,
			m_state->config->m_syscall_evt_drop_rate,
			m_state->config->m_syscall_evt_drop_max_burst,
			m_state->config->m_syscall_evt_simulate_drops);
	}

	// todo(XXX): skip for now and solve this later (not thread safe)
	// if (m_options.stats_filename != "")
	// {
	// 	string errstr;

	// 	if (!writer.init(inspector, m_options.stats_filename, m_options.stats_interval, errstr))
	// 	{
	// 		return run_result::fatal(errstr);
	// 	}
	// }

	//
	// Loop through the events
	//
	while(1)
	{

		rc = inspector->next(&ev);

		// todo(XXX): skip for now and solve this later (not thread safe)
		// writer.handle();

		// todo(XXX): not thread safe (we need to do this on the main thread and)
		//            sync with an atomic
		/* if(m_state->reopen_outputs)
		{
			falco_logger::log(LOG_INFO, "SIGUSR1 received, reopening outputs...\n");
			m_state->outputs->reopen_outputs();
			m_state->reopen_outputs = false;
		} */ 

		// todo(XXX): make these thread safe
		if(m_state->terminate.load(std::memory_order_acquire))
		{
			break;
		}
		else if (m_state->restart.load(std::memory_order_acquire))
		{
			break;
		}
		else if(rc == SCAP_TIMEOUT)
		{
			if(unlikely(ev == nullptr))
			{
				timeouts_since_last_success_or_msg++;
				if(timeouts_since_last_success_or_msg > m_state->config->m_syscall_evt_timeout_max_consecutives
					&& is_syscall_source)
				{
					std::string rule = "Falco internal: timeouts notification";
					std::string msg = rule + ". " + std::to_string(m_state->config->m_syscall_evt_timeout_max_consecutives) + " consecutive timeouts without event.";
					std::string last_event_time_str = "none";
					if(duration_start > 0)
					{
						sinsp_utils::ts_to_string(duration_start, &last_event_time_str, false, true);
					}
					std::map<std::string, std::string> o = {
						{"last_event_time", last_event_time_str},
					};
					auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
					m_state->outputs->handle_msg(now, falco_common::PRIORITY_DEBUG, msg, rule, o);
					// Reset the timeouts counter, Falco alerted
					timeouts_since_last_success_or_msg = 0;
				}
			}

			continue;
		}
		else if(rc == SCAP_EOF)
		{
			break;
		}
		else if(rc != SCAP_SUCCESS)
		{
			//
			// Event read error.
			//
			return run_result::fatal(inspector->getlasterr());
		}

		// Reset the timeouts counter, Falco successfully got an event to process
		timeouts_since_last_success_or_msg = 0;
		if(duration_start == 0)
		{
			duration_start = ev->get_ts();
		}
		else if(duration_to_tot_ns > 0)
		{
			if(ev->get_ts() - duration_start >= duration_to_tot_ns)
			{
				break;
			}
		}

		if(is_syscall_source && !sdropmgr.process_event(inspector, ev))
		{
			return run_result::fatal("Drop manager internal error");
		}

		if(!ev->simple_consumer_consider() && !m_options.all_events)
		{
			continue;
		}

		// if we are in live mode, we already have the engine idx
		// for the given source
		if (is_capture_mode)
		{
			source_idx = syscall_source_idx;
			if (ev->get_type() == PPME_PLUGINEVENT_E)
			{
				// note: here we can assume that the source index will be the same
				// in both the falco engine and the sinsp plugin manager. See the
				// comment in load_plugins.cpp for more details.
				source_idx = inspector->get_plugin_manager()->source_idx_by_plugin_id(*(int32_t *)ev->get_param(0)->m_val, source_idx_found);
				if (!source_idx_found)
				{
					return run_result::fatal("Unknown plugin ID in inspector: " + std::to_string(*(int32_t *)ev->get_param(0)->m_val));
				}
			}
		}

		// As the inspector has no filter at its level, all
		// events are returned here. Pass them to the falco
		// engine, which will match the event against the set
		// of rules. If a match is found, pass the event to
		// the outputs.
		unique_ptr<falco_engine::rule_result> res = m_state->engine->process_event(source_idx, ev);
		if(res)
		{
			m_state->outputs->handle_event(res->evt, res->rule, res->source, res->priority_num, res->format, res->tags);
		}

		num_evts++;
	}

	return run_result::ok();
}

application::run_result application::process_source_events(std::shared_ptr<sinsp> inspector, std::string source)
{
	syscall_evt_drop_mgr sdropmgr;
	// Used for stats
	double duration;
	scap_stats cstats;
	uint64_t num_evts = 0;
	run_result ret;
	bool is_capture_mode = source.empty();

	duration = ((double)clock()) / CLOCKS_PER_SEC;

	ret = do_inspect(inspector, source, sdropmgr,
					uint64_t(m_options.duration_to_tot*ONE_SECOND_IN_NS),
					num_evts);

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	inspector->get_capture_stats(&cstats);

	if(m_options.verbose)
	{
		if (source == falco_common::syscall_source)
		{
			fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\n",
			cstats.n_evts,
			cstats.n_drops);
		}

		if (!is_capture_mode)
		{
			fprintf(stderr, "(%s) ", source.c_str());
		}
		fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
			duration,
			num_evts,
			num_evts / duration);
	}

	if (source == falco_common::syscall_source)
	{
		sdropmgr.print_stats();
	}

	falco_logger::log(LOG_INFO, "Closing event source: " + source + "\n");
	inspector->close();

	return ret;
}

// todo(XXX): if only one source is active then run it on main thread
application::run_result application::process_events()
{
	// Notify engine that we finished loading and enabling all rules
	m_state->engine->complete_rule_loading();

	if(is_capture_mode())
	{
		// Try to open the trace file as a
		// capture file first.
		try {
			m_state->offline_inspector->open(m_options.trace_filename);
			falco_logger::log(LOG_INFO, "Reading system call events from file: " + m_options.trace_filename + "\n");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Could not open trace filename " + m_options.trace_filename + " for reading: " + e.what());
		}
		
		auto ret = process_source_events(m_state->offline_inspector, "");

		// Honor -M also when using a trace file.
		// Since inspection stops as soon as all events have been consumed
		// just await the given duration is reached, if needed.
		if(m_options.duration_to_tot > 0)
		{
			std::this_thread::sleep_for(std::chrono::seconds(m_options.duration_to_tot));
		}

		return ret;
	}

	std::vector<std::thread> source_threads;
	std::vector<run_result> source_threads_res;
	auto res = run_result::ok();
	for (auto source: m_state->enabled_sources)
	{
		auto inspector = m_state->source_inspectors[source];
		auto source_idx = source_threads_res.size();
		source_threads_res.push_back(run_result::ok());

		try 
		{
			falco_logger::log(LOG_INFO, "Opening event source: " + source + "\n");
			open_inspector(inspector, source, m_options.userspace);
			if(source == falco_common::syscall_source && !m_options.all_events)
			{
				inspector->start_dropping_mode(1);
			}
		}
		catch(std::exception &e)
		{
			source_threads_res[source_idx] = run_result::fatal(e.what());
		}
		
		if (!source_threads_res[source_idx].success)
		{
			res = source_threads_res[source_idx];
			break;
		}

		source_threads.push_back(std::thread([this, inspector, source, &source_threads_res, &source_idx]()
			{
				try 
				{
					source_threads_res[source_idx] = process_source_events(inspector, source);
				}
				catch(std::exception &e)
				{
					source_threads_res[source_idx] = run_result::fatal(e.what());
				}
			}));
	}
	
	// wait for all threads to be joined.
	// if a thread terminates with an error, we trigger the app termination
	// to force all other event streams to termiante too.
	// We accomulate the errors in a single run_result.
	size_t joined = 0;
	bool forced_termination = false;
	while (joined < source_threads.size())
	{
		if (!res.success && !forced_termination)
		{
			// todo(XXX): maybe use another signal, not the app-level one
			terminate();
			forced_termination = true;
		}

		for (size_t i = 0; i < source_threads.size(); i++)
		{
			if (source_threads[i].joinable())
			{
				source_threads[i].join();
				res = res.merge(source_threads_res[i]);
				joined++;
			}
		}
	}

	m_state->engine->print_stats();
	return res;
}
