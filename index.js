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
  try {
    const { results, log } = await parseSources(sources);

    // ensure results folder
    const outDir = path.join(__dirname, 'results');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    const outFile = path.join(outDir, 'filtered_list.txt');
    fs.writeFileSync(outFile, results.join('\n') + (results.length ? '\n' : ''), 'utf8');

    const logFile = path.join(outDir, 'last_run.log');
    fs.writeFileSync(logFile, log.join('\n'), 'utf8');

    console.log(new Date().toISOString(), `Done. ${results.length} entries written to ${path.relative(process.cwd(), outFile)}`);
  } catch (err) {
    console.error('Fatal error:', err);
    process.exit(2);
  }
}

main();
