// circom2's CLI rewrites paths to backslashes on Windows; WASI requires '/'.
const {CircomRunner,bindings}=require('circom2');const fs=require('fs');const path=require('path');
const preopens={'.':'.'};
const runner=new CircomRunner({args:['circuits/access_authorization.circom','--r1cs','--wasm','--sym','-o','circuits/build'],env:process.env,preopens,bindings:{...bindings,fs,exit:c=>process.exit(c),kill:s=>process.kill(process.pid,s)}});
runner.execute(fs.readFileSync(path.join(path.dirname(require.resolve('circom2')),'circom.wasm'))).catch(e=>{console.error(e);process.exit(1)});

