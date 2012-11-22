require 'sinatra'
require 'json'
require 'prowler'

class Message
  include Prowler::Priority

  def self.send(params)
    new(params).send
  end

  def initialize(params)
    if params.key?('alert')
      @alert = JSON.parse(params['alert'])
    end

    if params.key?('deployment')
      @deployment = JSON.parse(params['deployment'])
    end
  end

  def send
    if alert? || deployment? && notify_deployments?
      prowler = Prowler.new(:application => application, :api_key => api_key)

      if prowler.notify(message, description, options)
        "200 OK\n"
      else
        500
      end
    else
      "200 OK\n"
    end
  end

  private

  def alert?
    !!@alert
  end

  def api_key
    ENV['PROWL_API_KEY']
  end

  def application
    data['application_name']
  end

  def data
    @alert || @deployment
  end

  def deployment?
    !!@deployment
  end

  def description
    alert? ? data['long_description'] : data['description']
  end

  def downtime?
    data['severity'] == 'downtime'
  end

  def message
    alert? ? 'Alert' : 'Deployment'
  end

  def notify_deployments?
    !!ENV['NOTIFY_DEPLOYMENTS']
  end

  def options
    { :priority => priority, :url => url }
  end

  def priority
    if alert? && downtime?
      EMERGENCY
    elsif alert?
      HIGH
    else
      NORMAL
    end
  end

  def provider_key
    ENV['PROWL_PROVIDER_KEY']
  end

  def url
    alert? ? data['alert_url'] : data['deployment_url']
  end

end

post '/' do
  Message.send(params)
end

error do
  "500 Internal Server Error\n"
end

not_found do
  "404 Not Found\n"
end
