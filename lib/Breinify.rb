require 'net/https'
require 'json'
require 'base64'
require 'logger'

require File.join(File.dirname(__FILE__), '/Breinify/version.rb')

module Breinify

  ##
  # LOGGING
  # logger
  ##$log = Logger.new(STDOUT)
  $log = Logger.new('breinify.log', 'daily')
  $log.sev_threshold = Logger::ERROR

  ##
  # == Description
  # Provides the configuration of the library for the properties supplied.
  #
  # Possible parameters are:
  #    apiKey: The API-key to be used (mandatory).
  #    url: The url of the API
  #    activityEndpoint: The end-point of the API to send activities.
  #    lookupEndpoint: The end-point of the API to retrieve lookup results.
  #    secret: The secret attached to the API-key
  #    timeout: The maximum amount of time in milliseconds an API-call should take.
  #             If the API does not response after this amount of time, the call is cancelled.
  #
  # If no parameters are set the default parameters will be used.
  class BreinConfig

    ##
    #  default endpoint of activity
    DEF_ACTIVITY_ENDPOINT = '/activity'

    ##
    # default endpoint of lookup
    DEF_LOOKUP_ENDPOINT = '/lookup'

    ##
    # default breinify url
    DEF_URL = 'https://api.breinify.com'

    ##
    # default secret value
    DEF_SECRET = nil

    ##
    # default timeout (open in seconds)
    DEF_TIMEOUT = 6

    ##
    # default category
    DEF_CATEGORY = nil

    # instance members
    attr_accessor :url,
                  :api_key,
                  :secret,
                  :timeout,
                  :activity_endpoint,
                  :lookup_endpoint,
                  :category

    ##
    # === Description
    #
    def initialize
    end

    # create an instance of BreinConfig
    @@instance = BreinConfig.new

    # disallow creation
    #
    private_class_method :new

    ##
    # === Description
    # Returns the instance of BreinConfig (Singleton Pattern)
    #
    def self.instance
      return @@instance
    end

    ##
    # == Description
    # Sets the configuration for the API
    #
    def set_config(options = {})
      if options == nil
        $log.debug 'BreinifyConfig: values are nil'
        return
      end

      begin
        @api_key = options.fetch('apiKey', '')
        $log.debug ('apiKey: ' + @api_key)

        @url = options.fetch('url', DEF_URL)
        $log.debug ('url: ' + @url)

        @activity_endpoint = options.fetch('activityEndpoint', DEF_ACTIVITY_ENDPOINT)
        $log.debug ('ActivityEndpoint: ' + @activity_endpoint)

        @lookup_endpoint = options.fetch('lookupEndpoint', DEF_LOOKUP_ENDPOINT)
        $log.debug ('LookupEndpoint: ' + @lookup_endpoint)

        @secret = options.fetch('secret', DEF_SECRET)
        $log.debug ('Secret: ' + @secret)

        @timeout = options.fetch('timeout', DEF_TIMEOUT)
        $log.debug ('Timeout: ' + @timeout.to_s)

        @category = options.fetch('category', DEF_CATEGORY)
        $log.debug ('Category: ' + @category)
      rescue Exception => e
        $log.debug 'Exception caught: ' + e.message
        $log.debug '  Backtrace is: ' + e.backtrace.inspect
        return
      end
    end
  end

  ##
  # == Description
  # Sends an activity to the engine utilizing the API. The call is done as a POST request.
  # It is important that a valid API-key is configured prior to using this function.
  #
  class BreinActivity

    attr_accessor :http,
                  :request,
                  :init_done

    ##
    # Create an instance of BreinConfig
    #
    def initialize
      @brein_config = BreinConfig.instance
      @init_done = false
    end

    ##
    # Initializes the HTTP context
    def init_rest

      # if the initialization has already been done then go back
      if @init_done
        return
      end

      # url to use with activity endpoint
      full_url = @brein_config.url + @brein_config.activity_endpoint

      # retrieve all the options
      uri = URI(full_url)

      # Create the HTTP objects
      @http = Net::HTTP.new(uri.host, uri.port)
      @http.open_timeout = @brein_config.timeout
      @http.use_ssl = true if uri.scheme == 'https'

      # request itself
      @request = Net::HTTP::Post.new(uri.request_uri, 'Content-Type' => 'application/json')

      # indicates that the initializing for HTTP instance variables has been done
      @init_done = true
    end

    ##
    # Singleton Pattern
    @@instance = BreinActivity.new

    # disallow creation
    #
    private_class_method :new

    ##
    # returns the BreinActivity instance
    #
    def self.instance
      return @@instance
    end

    ##
    # Sends an activity to the engine.
    #
    def send_activity(options = {})

      if options == nil
        $log.debug 'Breinify activity: values are nil'
        return
      end

      begin
        # unix timestamp
        unix_timestamp = Time.now.getutc.to_i
        $log.debug 'Unix timestamp is: ' + unix_timestamp.to_s
        $log.debug 'activity values are: ' + options.to_s

        ## the following fields will be added (apiKey, unixTimestamp, secret [if set])
        data = options
        data['apiKey'] = @brein_config.api_key
        data['unixTimestamp'] = unix_timestamp

        # handles the secret / signature
        signature = handle_signature(options, unix_timestamp)
        if signature != nil
          data['signature'] = signature
        end

        ## retrieve the userAgent and set it if available
        user_agent = get_user_agent

        # fetch previous values - if they exists
        begin
          additional_values = options.fetch('user', {}).fetch('additional', {})
          if additional_values.empty?

            user_agent_hash = Hash.new
            user_agent_hash['userAgent'] = user_agent

            user_data = options.fetch('user', {})
            user_data['additional'] = user_agent_hash
          else
            additional_values['userAgent'] = user_agent
          end
        rescue
          $log.debug 'Could not handle userAgent information'
        end

        ## check if category has been set, otherwise add default from BreinConfig
        category_value = options.fetch('activity', {}).fetch('category', {})
        if category_value.empty?
          default_category = @brein_config.category
          category_data = options.fetch('activity', {})
          category_data['category'] = default_category
        end

        # prepare the body and send the request
        init_rest
        @request.body = data.to_json
        $log.debug 'JSON data request is: ' + @request.body.to_json.to_s

        # Send the request
        response = http.request(@request)
        $log.debug 'response from call is: ' + response.to_s

      rescue Exception => e
        $log.debug 'Exception caught: ' + e.message
        $log.debug '  Backtrace is: ' + e.backtrace.inspect
        return
      end

    end

    ##
    # == Description
    #
    # Tries to retrieve the user agent
    #
    def get_user_agent
      begin
        user_agent = request.user_agent
        $log.debug 'userAgent is: ' + user_agent
      rescue
        $log.debug 'Sorry, no userAgent can be detected'
        user_agent = nil
      end
      user_agent
    end

    ##
    # == Description
    #
    # This method will crypt the signature.
    #
    def handle_signature(options, unix_timestamp)
      signature = nil
      if @brein_config.secret != nil
        activity_data = options.fetch('activity', nil)
        activity_type = activity_data.fetch('type', nil)
        message = activity_type + unix_timestamp.to_s + '1'
        hash = OpenSSL::HMAC.digest('sha256', @brein_config.secret, message)
        signature = Base64.encode64(hash).strip
      end
      signature
    end

  end

  ##
  # == Description
  #
  # sets the Breinify Configuration of the library for the properties supplied.
  #
  #
  def self.set_config(options = {})
    BreinConfig.instance.set_config(options)
  end

  ##
  # == Description
  #
  # Sends an activity to the engine utilizing the API.
  # The call is done as a POST request.
  # It is important that a valid API-key is configured prior
  # to using this function.
  #
  def self.activity(options = {})
    BreinActivity.instance.send_activity(options)
  end

end

