DashDoorbell
============

A project aimed at turning an Amazon Dash button into a doorbell, written in Go.

Very early days. Currently monitors ARP traffic, and looks for requests from a pre-specified MAC address. When a request is seen, it kicks off a request to the Twilio API and sends a message to a phone number. Some basic rate-limiting enforced to try and prevent accidental (or otherwise) spamming. 

In the future, I'd like to send push notifications, perhaps have Webcam support, and allow multiple recepients for the notification. Audio Output would also be a plus, for that real-life doorbell feel. 


Building
========
It should be as easy as cloning the repository, running `go get .` -- this will resolve the dependencies (gopacket and twiliogo) and compile the project.


Usage
=====

```
./DashDoorbell -twilio_sid=<TWILIO_SID> -twilio_token=<TWILIO_TOKEN> -to_number=<RECIPIENT_NUMBER> -from_number=<FROM_NUMBER> -dash_mac=<DASH_BUTTON_MAC> -min_interval 30
```

