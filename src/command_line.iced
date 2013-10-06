_3s    = require './lib3s'
_optimist  = require('optimist').options('o',
        alias:    'output'
        describe: 'output file')
  .options('p',
        alias:    'passphrase'
        describe: 'passphrase as a parameter (not interactive)')
  .options('m',
        alias:    'message'
        describe: 'plaintext or ciphertext as a parameter, not a source file')
  .boolean('k')
  .alias('k', 'keep-original')
  .describe('k', 'do not delete original file when outputting to file')
  .boolean('s')
  .alias('s', 'stdout')
  .describe('s', 'stdout instead of file output')
  .usage('Usage: $0 <lock|unlock> [filename] [options]')

argv = _optimist.argv

###

  I M A G I N E D   E X A M P L E S

  3s lock

    3s lock foo.txt                                   # creates foo.txt.enc, deletes original
    3s lock foo.txt --output bar.enc                  # creates bar.enc, still deletes original
    3s lock foo.txt --keep-original                   # doesn't delete original
    3s lock foo.txt --keep-original --output bar.enc  # creates bar.enc, keeps original
    3s lock foo.txt --stdout                          # outputs foo.txt encrypted, keeps original
    3s lock foo.txt --passphrase 'eat a bag'          # doesn't ask for password
    3s lock --message 'hi there'                      # no file manipulation at all
    3s lock --output bar.enc --message 'hi there'
  
  3s unlock

    3s unlock foo.txt.enc                   # creates foo.txt, deletes original
    3s unlock foo.txt.enc --output bar.txt 
    etc.

###

exports.run = ->
  args = argv._
  if args.length < 1
    _optimist.showHelp()
    process.exit 1
  action = args[0]
  if args.length >= 2
    filename = args[1]
