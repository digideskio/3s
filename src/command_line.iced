constants   = require './constants'
path        = require 'path'
prompt      = require 'prompt'
fs          = require 'fs'
triplesec   = require 'triplesec'

_optimist   = require('optimist').string('o')
  .alias('o', 'output')
  .describe('o', 'output file')
  .string('p')
  .alias('p', 'passphrase')
  .describe('p','passphrase as a parameter (not interactive)')
  .options('m',
        alias:    'message'
        describe: 'plaintext or ciphertext as a parameter, not a source file')
  .string('m')
  .boolean('k')
  .alias('k', 'keep')
  .describe('k', 'do not delete original file when outputting to file')
  .boolean('s')
  .alias('s', 'stdout')
  .describe('s', 'stdout instead of file output')
  .usage('Usage: $0 <lock|unlock> [filename] [options]')

argv = _optimist.argv

###

  O P T I O N S

    action:   string; (mandatory) "lock" or "unlock"
    filename: string; either this or message expected
    message:  string; either this or filename expected
    stdout:   bool;   if this then output to stdout    
    output:   string; filename; determined automatically if stdout not set and filename passed

  I M A G I N E D   E X A M P L E S

  3s lock

    3s lock foo.txt                                   # creates foo.txt.3s, deletes original
    3s lock foo.txt --output bar.3s                   # creates bar.3s, still deletes original
    3s lock foo.txt --keep                            # doesn't delete original
    3s lock foo.txt --keep --output bar.3s            # creates bar.3s, keeps original
    3s lock foo.txt --stdout                          # outputs foo.txt encrypted, keeps original
    3s lock foo.txt --passphrase 'eat a bag'          # doesn't ask for password
    3s lock --message 'hi there'                      # no file manipulation at all
    3s lock --output bar.3s --message 'hi there'
  
  3s unlock

    3s unlock foo.txt.3s                   # creates foo.txt, deletes original
    3s unlock foo.txt.3s --output bar.txt 
    etc.

###

# ------------------------------------------------------------------

exit_err = (txt, no_show_help) ->
  process.stdout.write "Error: #{txt}\n" if txt
  _optimist.showHelp() unless no_show_help
  process.exit 1

# ------------------------------------------------------------------

file_to_buffer = (opts, cb) ->
  fname = opts.filename

  if opts.action is "lock"
    read_enc = "binary"
    buffer_enc = "binary"
  else
    read_enc = "utf8"
    buffer_enc = "base64"

  await fs.stat fname, defer err, stats
  if err
    exit_err "failed to find file #{fname}", true
  else if stats.size > (m = constants.max_srcfile_bytes)
    exit_err "source file too large (#{stats.size}); max=#{m}"
  else if stats.isDirectory()
    exit_err "source file is a directory"
  await fs.readFile fname, {encoding: read_enc}, defer err, data
  if err
    exit_err "failed to read file #{fname} (#{err})"
  opts.input_buffer = new Buffer data, buffer_enc
  cb()

# ------------------------------------------------------------------

go = (opts, cb) ->
  #console.log opts
  fn = if opts.action is "lock" then triplesec.encrypt else triplesec.decrypt
  await fn
    data:           opts.input_buffer
    key:            opts.passphrase_buffer
    progress_hook:  (o) ->
  , defer err, buff
  if err and opts.action is "unlock"
    exit_err "check passphrase or input.", true
  else if err
    exit_err "an unknown error occurred. Exiting.", true
  else
    if opts.action is 'lock'
      write_enc = 'utf8'
      out       = buff.toString 'base64'
    else
      write_enc = 'utf8'
      out       = buff
    if opts.stdout
      process.stdout.write out
    if opts.output
      await fs.writeFile opts.output, out, {encoding: write_enc}, defer err
      if err?
        exit_err "could not write #{opts.output}.", true
      else if (not opts.keep) and (opts.filename?)
        await fs.unlink opts.filename, defer err
        if err?
          exit_err "failed to delete #{opts.filename}.", true
    cb()

# ------------------------------------------------------------------

collect_user_input = (opts, cb) ->
  prompt.message    = ""
  prompt.delimiter  = ""
  prompt.start()
  while not opts.passphrase
    if opts.action is "lock"
      await prompt.get {
        properties:
          p1:
            hidden:       true
            description:  "   Enter a passphrase: "
            type:         "string"
            pattern:      /^.+$/
          p2:
            hidden:       true
            description:  "Verify the passphrase: "
            type:         "string"
            pattern:      /^.+$/
      }, defer err, x
    else 
      await prompt.get {
        properties:
          p1:
            hidden:       true
            description:  "   Enter your passphrase: "
            type:         "string"
            pattern:      /^.+$/
      }, defer err, x
    if err
      exit_err "user requested exit...", true    
    else if (opts.action is "lock") and (x.p1 isnt x.p2)
      console.log "passwords didn't match"
    else if not x.p1.length
      console.log "password empty"
    else
      opts.passphrase = x.p1
  cb()

# ------------------------------------------------------------------

auto_outfile = (opts, cb) -> 
  if opts.action is "lock"
    opts.output = opts.filename + ".3s"
  else
    if path.extname(opts.filename) is ".3s"
      opts.output = opts.filename[...-3]
    else
      exit_err "expected -o, -s, or filename ending with .3s", true
  cb()

# ------------------------------------------------------------------

cleanse = (opts) ->
  delete opts.passphrase if opts.passphrase?
  delete opts.message    if opts.message?

# ------------------------------------------------------------------
# collect and verify params
# ------------------------------------------------------------------

run = exports.run = ->
  opts = {}
  args = argv._
  if args.length < 1 then exit_err()
  opts.action = args[0]
  if args.length >= 2
    opts.filename = args[1]
  if argv.stdout?     then opts.stdout  = argv.stdout
  if (typeof argv.output) is 'string'    then opts.output = argv.output
  if (typeof argv.message) is 'string'    then opts.message = argv.message
  if (typeof argv.passphrase) is 'string' then opts.passphrase = argv.passphrase
  if argv.keep? then opts.keep = argv.keep
  if not (opts.filename or opts.message) then exit_err "expecting either a filename or a message"
  if opts.filename and opts.message then exit_err "not expecting both a filename (#{opts.filename}) and a message"
  if opts.filename
    await file_to_buffer opts, defer()
    if (not opts.stdout) and (not opts.output)
      await auto_outfile opts, defer()
  else
    enc = if opts.action is 'unlock' then 'base64' else 'binary'
    opts.input_buffer = new Buffer opts.message, enc
    if not opts.output
      opts.stdout = true
  if opts.output?
    if opts.filename and (path.resolve(opts.filename) is path.resolve(opts.output))
      exit_err "3s does not support outputting to input file", true
    await fs.exists opts.output, defer exists
    if exists
      exit_err "output file #{opts.output} exists."
  await collect_user_input opts, defer()
  opts.passphrase_buffer = new Buffer opts.passphrase
  cleanse opts
  await go opts, defer()
  process.exit 0

# ------------------------------------------------------------------
# ------------------------------------------------------------------

if not module.parent
  run()

# ------------------------------------------------------------------
