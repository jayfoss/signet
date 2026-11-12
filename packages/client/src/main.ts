/* eslint-disable no-console */
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { run } from './cli';

/** SIGNET_HOME picks the client directory (default ~/.signet). Each client, agents included, has its own. */
async function confirm(question: string): Promise<boolean> {
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await prompt.question(`${question} [y/N] `);
  prompt.close();
  return /^y(es)?$/i.test(answer.trim());
}

run(process.argv.slice(2), { home: process.env.SIGNET_HOME ?? join(homedir(), '.signet'), out: (line) => console.log(line), confirm }).catch(
  (error: Error) => {
    console.error(`signet: ${error.message}`);
    process.exit(1);
  },
);
