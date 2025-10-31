/**
 * Entry point.
 * Reads sources.json (list of URLs), runs parser, writes results to results/filtered_list.txt
 * Logs progress to console.
 */
const fs = require('fs');
const path = require('path');
const { parseSources } = require('./parser');
async function main() {
  console.log(new Date().toISOString(), 'Starting VPN parser run');
  const sourcesPath = path.join(__dirname, 'sources.json');
  if (!fs.existsSync(sourcesPath)) {
    console.error('sources.json not found. Create it with array of URLs to parse.');
    process.exit(1);
  }
  const sources = JSON.parse(fs.readFileSync(sourcesPath, 'utf8'));
  console.log(`Loaded ${sources.length} sources from sources.json`);
  try {
    const { results, log } = await parseSources(sources);
    console.log(`Parser completed: ${results.length} results, ${log.length} log entries`);
    // ensure results folder
    const outDir = path.join(__dirname, 'results');
    if (!fs.existsSync(outDir)) {
      fs.mkdirSync(outDir);
      console.log('Created results directory');
    }
    // write filtered results
    const filteredPath = path.join(outDir, 'filtered_list.txt');
    fs.writeFileSync(filteredPath, results.join('\n'));
    console.log(`Written ${results.length} entries to ${filteredPath}`);
    // write log
    const logPath = path.join(outDir, 'last_run.log');
    fs.writeFileSync(logPath, log.join('\n'));
    console.log(`Written ${log.length} log entries to ${logPath}`);
  } catch (error) {
    console.error('Error in main:', error);
    process.exit(1);
  }
}
main().catch(console.error);
