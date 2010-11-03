require "rubygems"
require "hpricot"
require "digest/md5"
require "scrobbler"

module Scrobbler
    
    # Authentication 2.0
    class Auth
        @@AUTH_VERSION = "2.0"
        @@AUTH_URL     = "http://ws.audioscrobbler.com" 
        
        attr_reader :session_id, :username, :subscriber
        attr_accessor :api_key, :api_secret
        
        # Contructor.
        #
        # @param api_key Last.FM API key
        # @param api_secret Last.FM API secret
        # @raise ArgumentError
        def initialize(args = {})
            @api_key = args[:api_key]
            @api_secret = args[:api_secret]
            
            raise ArgumentError, "API key required" unless @api_key
            raise ArgumentError, "API secret required" unless @api_secret
        end
        
        # Constructs api method signatures.
        #
        # @see http://www.last.fm/api/webauth#6
        # @param method Last.FM method
        # @param params Optional method parameters
        def sign_method(method, parameters = {})
            raise ArgumentError, "Method required" if method.empty?
            
            parameters["api_key"] = @api_key
            parameters["method"] = method
            
            # Sort alphabetically and concatenate into one string using namevalue scheme.
            signature_string = parameters.sort.join("")
            
            # And finally append the api secret
            signature_string += @api_secret

            Digest::MD5.hexdigest(signature_string)
        end
        
        # Fetch a session key for a user. The third step in the authentication process.
        #
        # @see http://www.last.fm/api/show?service=125
        # @param token A 32-character ASCII hexadecimal MD5 hash returned by step 1 of the authentication process
        def new_session!(token)
            raise ArgumentError, "Token required" if token.length != 32
            
            method = "auth.getSession"
            signature = self.sign_method(method, "token" => token)
            url = "/#{@@AUTH_VERSION}/?method=#{method}&token=#{token}&api_key=#{@api_key}&api_sig=#{signature}"
            connection = REST::Connection.new(@@AUTH_URL)

            result = connection.get(url)
            lfm = Hpricot(result).search("lfm")

            raise Exception, "Last.FM response failed with unknown error, I'm lost!" if lfm.empty?            
            # @todo Introduce propper Exceptions for Last.FM errors
            raise lfm.search("error").inner_html unless lfm.search("error").empty?
            
            @username = lfm.search("name").inner_html
            @session_id = lfm.search("key").inner_html
            @subscriber = lfm.search("subscriber").inner_html == "1"
        end
        
        # Url to send user to
        #
        # @see http://www.last.fm/api/webauth#2
        def token_url
            "http://www.last.fm/api/auth?api_key=#{@api_key}"
        end
    end
end