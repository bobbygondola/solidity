/*
    This file is part of solidity.

    solidity is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    solidity is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <test/tools/ossfuzz/yulProto.pb.h>
#include <test/tools/ossfuzz/protoToYul.h>

#include <test/tools/ossfuzz/SolidityEvmoneInterface.h>

#include <libyul/AssemblyStack.h>
#include <libyul/Exceptions.h>

#include <libyul/backends/evm/EVMDialect.h>

#include <libevmasm/Instruction.h>

#include <liblangutil/EVMVersion.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <fstream>
#include <libyul/backends/evm/EVMCodeTransform.h>

using namespace solidity;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::yul;
using namespace solidity::yul::test;
using namespace solidity::yul::test::yul_fuzzer;
using namespace solidity::langutil;
using namespace std;

static evmc::VM evmone = evmc::VM{evmc_create_evmone()};

DEFINE_PROTO_FUZZER(Program const& _input)
{
	ProtoConverter converter;
	string yul_source = converter.programToString(_input);
	// Fuzzer also fuzzes the EVM version field.
	langutil::EVMVersion version = converter.version();
	EVMHost hostContext(version, evmone);
	hostContext.reset();

	if (const char* dump_path = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		ofstream of(dump_path);
		of.write(yul_source.data(), static_cast<streamsize>(yul_source.size()));
	}

	if (yul_source.size() > 1200)
		return;

	YulStringRepository::reset();

	auto assemble = [](
		langutil::EVMVersion _version,
		solidity::frontend::OptimiserSettings _settings,
		string const& _yulSource
	) -> bytes
	{
		AssemblyStack stack(
			_version,
			AssemblyStack::Language::StrictAssembly,
			_settings
		);

		// Parse protobuf mutated YUL code
		if (
			!stack.parseAndAnalyze("source", _yulSource) ||
			!stack.parserResult()->code ||
			!stack.parserResult()->analysisInfo ||
			!Error::containsOnlyWarnings(stack.errors())
		)
			yulAssert(false, "Proto fuzzer generated malformed program");

		return stack.assemble(AssemblyStack::Machine::EVM).bytecode->bytecode;
	};

	solidity::frontend::OptimiserSettings settings = solidity::frontend::OptimiserSettings::full();
	settings.runYulOptimiser = false;
	settings.optimizeStackAllocation = false;
	bytes unoptimisedByteCode;
	try
	{
		unoptimisedByteCode = assemble(version, settings, yul_source);
	}
	catch (solidity::yul::StackTooDeepError const&)
	{
		return;
	}

	auto deployCode = [](
		bytes const& _input,
		EVMHost& _hostContext
	) -> evmc::result
	{
		// Zero initialize all message fields
		evmc_message msg = {};
		// Gas available (value of type int64_t) is set to its maximum
		// value.
		msg.gas = std::numeric_limits<int64_t>::max();
		solAssert(
			_input.size() <= 0xffff,
			"Deployed byte code is larger than the permissible 65535 bytes."
		);
		uint8_t inputSizeHigher = static_cast<uint8_t>(_input.size() >> 8);
		uint8_t inputSizeLower = _input.size() & 0xff;
		bytes deployCode = bytes{
			0x38, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x61,
			inputSizeHigher, inputSizeLower,
			0x60, 0x00, 0xf3
		} + _input;
		msg.input_data = deployCode.data();
		msg.input_size = deployCode.size();
		msg.kind = EVMC_CREATE;
		return _hostContext.call(msg);
	};
	auto initCallMsg = [](evmc_address _addr) -> evmc_message
	{
		evmc_message call = {};
		call.gas = std::numeric_limits<int64_t>::max();
		call.destination = _addr;
		call.kind = EVMC_CALL;
		return call;
	};
	auto debug = [](
		langutil::EVMVersion _version,
		bytes const& _byteCode,
		evmc::result& _result
	)
	{
		cout << "EVM version: " << _version.name() << endl;
		cout << util::toHex(_byteCode) << endl;
		cout << "Gas left: " << _result.gas_left << endl;
		cout << "Status code: " << _result.status_code << endl;
		cout << "Create Address: " << EVMHost::convertFromEVMC(_result.create_address) << endl;
	};
	evmc::result deployResult = deployCode(unoptimisedByteCode, hostContext);
	if (deployResult.status_code != EVMC_SUCCESS)
		return;
	debug(version, unoptimisedByteCode, deployResult);
	auto callMessage = initCallMsg(deployResult.create_address);
	evmc::result callResult = hostContext.call(callMessage);
	// We don't care about EVM One failures other than EVMC_REVERT
	solAssert(
		callResult.status_code != EVMC_REVERT,
		"SolidityEvmoneInterface: EVM One reverted"
	);
	ostringstream unoptimizedStorage;
	hostContext.print_storage_at(deployResult.create_address, unoptimizedStorage);

	settings.optimizeStackAllocation = true;
	bytes optimisedByteCode;
	try
	{
		optimisedByteCode = assemble(version, settings, yul_source);
	}
	catch (solidity::yul::StackTooDeepError const&)
	{
		return;
	}
	evmc::result deployResultOpt = deployCode(optimisedByteCode, hostContext);
	debug(version, optimisedByteCode, deployResultOpt);
	solAssert(
		deployResultOpt.status_code == EVMC_SUCCESS,
		"Evmone: Optimized contract creation failed"
	);
	auto callMessageOpt = initCallMsg(deployResultOpt.create_address);
	evmc::result callResultOpt = hostContext.call(callMessageOpt);
	// We don't care about EVM One failures other than EVMC_REVERT
	solAssert(
		callResultOpt.status_code != EVMC_REVERT,
		"SolidityEvmoneInterface: EVM One reverted"
	);
	ostringstream optimizedStorage;
	hostContext.print_storage_at(deployResultOpt.create_address, optimizedStorage);
	cout << "Unoptimised storage" << endl;
	cout << unoptimizedStorage.str() << endl;
	cout << "Optimised storage" << endl;
	cout << optimizedStorage.str() << endl;
	solAssert(
		unoptimizedStorage.str() == optimizedStorage.str(),
		"Storage of unoptimised and optimised stack reused code do not match."
	);
}

