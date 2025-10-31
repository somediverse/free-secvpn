/**
 * Entry point.
 * Reads sources.json (list of URLs), runs parser, writes results to results/filtered_list.txt
 * Logs progress to console.
 */
const fs = require('fs').promises; // Изменено для асинхронных операций
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
      await fs.mkdir(outDir);
      console.log('Created results directory');
    }
    
    // write filtered results asynchronously
    console.log('Writing filtered_list.txt...');
    const filteredPath = path.join(outDir, 'filtered_list.txt');
    await fs.writeFile(filteredPath, results.join('\n') + '\n');
    console.log(`Written ${results.length} entries to ${filteredPath}`);
    
    // write log asynchronously
    console.log('Writing last_run.log...');
    const logPath = path.join(outDir, 'last_run.log');
    await fs.writeFile(logPath, log.join('\n') + '\n');
    console.log(`Written ${log.length} log entries to ${logPath}`);
    
    console.log(new Date().toISOString(), 'Done. All operations completed successfully');
    
  } catch (error) {
    console.error('Error in main:', error);
    process.exit(1);
  }
}
main().catch(console.error);
