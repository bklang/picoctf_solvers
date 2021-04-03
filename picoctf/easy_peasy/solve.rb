#!/usr/bin/env ruby -w
require 'socket'

# Set environment variable DEBUG=true to see the interactions with the server

class Interactor
  FLAG_REGEX = /\r?\n([A-z0-9]{64})\r?\n/
  KNOWN_PLAINTEXT = "A" * 32
  def initialize(local_or_remote)
    case local_or_remote
    when "local"
      # Set "key" and "flag" files to ensure otp.py runs successfully
      set_flag_and_key
      @io = IO.popen "python otp.py", "r+"
    when "remote"
      @io = TCPSocket.new "mercury.picoctf.net", 36981
    else
      raise "Must be either 'remote' for the live crack, or 'local' for testing with otp.py"
    end
  end

  def run
    output, flag = read_until_flag

    puts "DETECTED FLAG: #{flag}"

    read_until_prompt(output)

    # Need to send 50,000 - 32 characters to cause the pad to loop around
    49.times do
      write "A" * 1000
      read_until_prompt
    end
    write "A" * (1000-32)

    read_until_prompt

    # The OTP should now be back in the start position. Provide known plaintext
    write KNOWN_PLAINTEXT
    output = read_until_prompt
    known_ciphertext = output.match(FLAG_REGEX)[1]
    known_cipherbytes = to_byte_array known_ciphertext

    # Determine the key by XORing the known ciphertext with the known plaintext
    known_plaintext = KNOWN_PLAINTEXT.split('').map{|chr| chr.ord}
    key = []
    known_plaintext.each_index do |i|
      key << (known_plaintext[i] ^ known_cipherbytes[i])
    end

    # Use the newly found key to decrypt the flag provided in the beginning
    flag_cipherbytes = to_byte_array flag
    decoded_flag = []
    key.each_index do |i|
      decoded_flag << (key[i] ^ flag_cipherbytes[i])
    end

    # .map{|byte| byte.chr} => take each number and print its ASCII value (eg. 65 => "A")
    puts "Found the key: " + decoded_flag.map{|byte| byte.chr}.join('')
  end

  def to_byte_array(str)
    # .scan(/../) => split the string into an array of 2-character groups
    # .map{|byte| byte.to_i(16)} => interpret each 2-character group as a hexadecimal number
    str.scan(/../).map {|byte| byte.to_i(16)}
  end

  def read_until_flag
    output = ""
    until match = output.match(FLAG_REGEX)
      output << @io.readpartial(4096)
    end
    debug output
    [output, match[1]]
  end

  def read_until_prompt(output = "")
    until output =~ /What data would you like to encrypt\? $/
      output << @io.readpartial(4096)
    end
    debug output
    output
  end

  def write(str)
    debug str
    @io.puts str
  end

  def debug(log_txt)
    ENV['DEBUG'] && puts(log_txt)
  end

  def set_flag_and_key
    File.open("flag", "w") { |file| file.write "THIS IS THE FLAG IT IS A DOOZIEE" }
    File.open("key", "w") { |file| file.write "A" * 50_000 }
  end
end

Interactor.new(ARGV[0]).run
