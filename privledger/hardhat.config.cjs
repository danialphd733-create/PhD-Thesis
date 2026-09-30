require('@nomicfoundation/hardhat-ethers');
const {subtask}=require('hardhat/config');
const {TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD}=require('hardhat/builtin-tasks/task-names');
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(async ({solcVersion},hre,runSuper)=>solcVersion==='0.8.28'?{compilerPath:require.resolve('solc/soljson.js'),isSolcJs:true,version:solcVersion,longVersion:require('solc').version()}:runSuper());
module.exports={solidity:{version:'0.8.28',settings:{optimizer:{enabled:true,runs:200},viaIR:true}},networks:{hardhat:{chainId:31337},localhost:{url:'http://127.0.0.1:8545'}},paths:{tests:'./tests/contracts'},mocha:{timeout:180000}};
