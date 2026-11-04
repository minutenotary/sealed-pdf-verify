import process from 'node:process';
import { runCli } from './main.js';

const code = await runCli(process.argv.slice(2), {
  out: (line) => {
    process.stdout.write(line + '\n');
  },
  err: (line) => {
    process.stderr.write(line + '\n');
  },
});
process.exitCode = code;
