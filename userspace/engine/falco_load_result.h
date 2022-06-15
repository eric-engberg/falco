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

#pragma once

#include <string>
#include <nlohmann/json.hpp>

// Represents the result of loading a rules file.
class falco_load_result {
public:

	enum error_code {
		FE_LOAD_ERR_FILE_READ = 0,
		FE_LOAD_ERR_YAML_PARSE,
		FE_LOAD_ERR_YAML_VALIDATE,
		FE_LOAD_ERR_COMPILE_CONDITION,
		FE_LOAD_ERR_COMPILE_OUTPUT,
		FE_LOAD_ERR_VALIDATE
	};

	// The error code as a string
	static const std::string& error_code_str(error_code ec);

	// A short string representation of the error
	static const std::string& error_str(error_code ec);

	// A longer description of what the error represents and the
	// impact.
	static const std::string& error_desc(error_code ec);

	enum warning_code {
		FE_LOAD_UNKNOWN_SOURCE = 0,
		FE_LOAD_UNSAFE_NA_CHECK,
		FE_LOAD_NO_EVTTYPE,
		FE_LOAD_UNKNOWN_FIELD,
		FE_LOAD_UNUSED_MACRO,
		FE_LOAD_UNUSED_LIST,
		FE_LOAD_UNKNOWN_ITEM
	};

	// The warning code as a string
	static const std::string& warning_code_str(warning_code ec);

	// A short string representation of the warning
	static const std::string& warning_str(warning_code ec);

	// A longer description of what the warning represents and the
	// impact.
	static const std::string& warning_desc(warning_code ec);

	// If true, the rules were loaded successfully and can be used
	// against events. If false, there were one or more
	// errors--use one of the as_xxx methods to return information
	// about why the rules could not be loaded.
	virtual bool successful() = 0;

	// If true, there were one or more warnings. successful() and
	// has_warnings() can both be true if there were only warnings.
	virtual bool has_warnings() = 0;

	// This returns a short string with the success value and
	// a list of errors/warnings. Suitable for simple one-line
	// display.
	virtual const std::string& as_summary() = 0;

	// This contains a human-readable version of the result, with
	// full details on the result including document
	// locations/context. Suitable for display to end users.
	virtual const std::string& as_string() = 0;

	// This contains the full result structure as json, suitable
	// for automated parsing/interpretation downstream.
	virtual const nlohmann::json& as_json() = 0;
};
