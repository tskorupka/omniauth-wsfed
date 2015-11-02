require 'erb'

module OmniAuth
  module Strategies
    class WSFed

      class AuthRequest
        include ERB::Util

        SIGNIN_PARAM = 'wsignin1.0'

        attr_reader :strategy_settings, :args

        def initialize(settings, args = {})
          raise ArgumentError.new('OmniAuth-WSFed settings cannot be nil.') if settings.nil?

          @strategy_settings  = settings
          @args               = args
        end

        def redirect_url
          if args[:whr].nil? && strategy_settings[:home_realm_discovery_path]
            strategy_settings[:home_realm_discovery_path]
          else
            wsfed_signin_request
          end
        end

        def wsfed_signin_request
          wa      = SIGNIN_PARAM
          wtrealm = url_encode(strategy_settings[:realm]).downcase
          wreply  = url_encode(strategy_settings[:reply]).downcase
          time    = Time.now.strftime('%Y-%m-%dT%TZ')
          wct     = url_encode(time).downcase.gsub('z', 'Z').gsub('t', 'T')
          whr     = url_encode(args[:whr]).downcase

          query_string = "?wa=#{wa}&wtrealm=#{wtrealm}&wct=#{wct}&wreply=#{wreply}&wctx=#{}"

          unless whr.nil? or whr.empty?
            query_string = "#{query_string}&whr=#{whr}"
          end

          puts '[ADFS - Custom - STSG Company][INFO] - Begin wsfed_signin_request'
          puts "[ADFS - Custom - STSG Company][INFO] - Time is #{time}"
          puts "[ADFS - Custom - STSG Company][INFO] - After url_encode is #{wct}"
          puts "[ADFS - Custom - STSG Company][INFO] - End wsfed_signin_request #{strategy_settings[:issuer] + query_string}"

          strategy_settings[:issuer] + query_string
        end

      end

    end
  end
end