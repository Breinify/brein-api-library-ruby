

<p align="center">
  <img src="https://raw.githubusercontent.com/Breinify/brein-api-library-java/master/documentation/img/logo.png" alt="Breinify API Java Library" width="250">
</p>

<p align="center">
Breinify's DigitalDNA API puts dynamic behavior-based, people-driven data right at your fingertips.
</p>

[![version][gem-version]][gem-url]

[![License][license-image]][license-url]


### Step By Step Introduction

#### What is Breinify's DigitialDNA

Breinify's DigitalDNA API puts dynamic behavior-based, people-driven data right at your fingertips. We believe that in many situations, a critical component of a great user experience is personalization. With all the data available on the web it should be easy to provide a unique experience to every visitor, and yet, sometimes you may find yourself wondering why it is so difficult.

Thanks to **Breinify's DigitalDNA** you are now able to adapt your online presence to your visitors needs and **provide a unique experience**. Let's walk step-by-step through a simple example.

### Quick start

#### Step 1: Installation

Add this line to your application's Gemfile:

```ruby
gem 'Breinify'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install Breinify


#### Step 2: Configure the library

In order to use the library you need a valid API-key, which you can get for free at [https://www.breinify.com](https://www.breinify.com). In this example, we assume you have the following api-key:

**772A-47D7-93A3-4EA9-9D73-85B9-479B-16C6**

```ruby
# configure 
Breinify.setConfig({'apiKey' => '772A-47D7-93A3-4EA9-9D73-85B9-479B-16C6',
                    'activityEndpoint' => '/activity',
                    'lookupEndpoint' => '/lookup',
                    'secret' => 'lmcoj4k2ttzz66qamhg!=',
                    'timeout' => 1000,
                    'url' => 'https://api.breinify.com'})
                    

```

The Breinify class is now configured with a valid configuration object.


#### Step 3: Start using the library

##### Placing activity triggers

The engine powering the DigitalDNA API provides two endpoints. The first endpoint is used to inform the engine about the activities performed by visitors of your site. The activities are used to understand the user's current interest and infer the intent. It becomes more and more accurate across different users and verticals as more activities are collected. It should be noted, that any personal information is not stored within the engine, thus each individual's privacy is well protected. The engine understands several different activities performed by a user, e.g., landing, login, search, item selection, or logout.

The engine is informed of an activity by executing *Breinify.activity(...)*. 

```Ruby
# invoke the activity call containing the mandatory fields
Breinify.activity({'user' => {'Fred.Firestone@email.com',
                                'sessionId' => 'r3V2kDAvFFL_-RBhuc_-Dg'},
                     'activity' => {
                         'description' => 'this is the description',
                         'type' => 'checkout',
                         'category' => 'food'
                     }}
```

That's it! The call will be invoked. 

The following snippets shows a different approach and the fields that are currently supported:

```Ruby

  userData = Hash.new
  userData['email'] = 'fred.firestone@email.com'
  userData['lastName'] = 'Fred'
  userData['firstName'] = 'Firestone'
  userData['sessionId'] = 'aa8!scdfsf8988'

  additionalData = Hash.new
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

  Breinify.activity(requestData)

```

That's it! The call will be invoked. 



### Further information


### License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

### Further links
To understand all the capabilities of Breinify's DigitalDNA API, take a look at:

* [Breinify's Website](https://www.breinify.com).
