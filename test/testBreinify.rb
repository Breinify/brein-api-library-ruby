require_relative '../lib/Breinify'

# configuration without secret
#Breinify.setConfig({:apiKey => '41B2-F48C-156A-409A-B465-317F-A0B4-E0E8',
#                    :baseUrl => 'https://api.breinify.com',
#                    :activityEndpoint => '/activity',
#                    :lookupEndpoint => '/lookup',
#                    :secret => null,
#                    :timeout => 1000,
#                    :url => 'https://api.breinify.com'})

# configuration with secret

#test with nil

begin
  user_agent = request.env['HTTP_USER_AGENT']
rescue
  puts "No user_agent"
end

begin
  ipaddress = request.env['HTTP_X_REAL_IP']
rescue
  puts 'No IP Address determined'
end


Breinify.set_config(nil)


Breinify.set_config({'apiKey' => 'CA8A-8D28-3408-45A8-8E20-8474-06C0-8548',
                     'activityEndpoint' => '/activity',
                     'lookupEndpoint' => '/lookup',
                     'secret' => 'lmcoj4k27hbbszzyiqamhg==',
                     'timeout' => 12,
                     'url' => 'https://api.breinify.com',
                     'category' => 'sales'})


# activity call
1.upto(10) {

  # test with nil
  Breinify.activity(nil)

  # activity without category
  Breinify.activity({'user' => {'firstName' => 'Maria',
                                'email' => 'user.email@me.com',
                                'lastName' => 'Tester',
                                'sessionId' => 'r3V2kDAvFFL_-RBhuc_-Dg'},
                     'activity' => {
                         'description' => 'this is the description',
                         'type' => 'checkout'
                     }
                    })

  userData = Hash.new
  userData['email'] = 'user.email@me.com'
  userData['lastName'] = 'Test'
  userData['firstName'] = 'Maria'
  userData['sessionId'] = 'xxxxxdddd'

  additionalData = Hash.new
  #additionalData['userAgent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586'
  additionalData['referrer'] = 'https://sampleurl.com/track'
  additionalData['url'] = 'https://sampleurl.com/'

  userData['additional'] = additionalData

  activityData = Hash.new
  activityData['description'] = 'this is the description'
  activityData['type'] = 'checkout'

  requestData = Hash.new
  requestData['user'] = userData
  requestData['activity'] = activityData
  requestData['ipAddress'] = '10.111.222.333'




  Breinify.activity({'user' => {'firstName' => 'Maria',
                                'email' => 'user.email@me.com',
                                'lastName' => 'Tester',
                                'sessionId' => 'r3V2kDAvFFL_-RBhuc_-Dg'},
                     'activity' => {
                         'description' => 'this is the description',
                         'type' => 'checkout',
                         'category' => 'food',
                         'tags' => {'string' => 'string',
                                    'int' => 5,
                                    'double' => 9.1,
                                    'array' => %w(a b c),
                                    'null' => nil}
                     }
                    })


  Breinify.activity(requestData)


  Breinify.activity({'user' => {'firstName' => 'Maria',
                                'email' => 'user.email@me.com',
                                'lastName' => 'Tester',
                                'sessionId' => 'r3V2kDAvFFL_-RBhuc_-Dg',
                                'additional' => {
                                    'referrer' => 'https://teesummer.com/track',
                                    'url' => 'https://teesummer.com/track/recover'
                                }},
                     'activity' => {
                         'description' => 'this is the description',
                         'type' => 'checkout',
                         'category' => 'food'
                     }})


}






