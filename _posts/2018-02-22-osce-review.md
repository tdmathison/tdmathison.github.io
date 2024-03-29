---
title: "OSCE Review"
date: 2018-02-22 12:00:00 -0700
categories: [Blogging, Offensive-Security]
tags: [offensive-security, osce, penetration-testing, hacking]
---

## General thoughts
With past experience with Offensive Security, the training format was familiar which sped things up a bit for consuming the content.  The Offensive Security Certified Expert (OSCE) course is similar in that regard but very different in terms of content.  The biggest difference is in how focused one is over the other.

The OSCE is primarily focused on exploit development with a little bit of web application and networking discussion in regards to common issues.  The buffer overflow exercise from the OSCP is about 80% the type of work done in the OSCE but just taken farther. That was the most enjoyable part of the OSCP for me and as expected the OSCE experience overall was more enjoyable for me as well.

## The OSCE Lab
The course for this certification is called "Cracking The Perimeter" and the sign up for the course has a small gated check to complete the registration. This is really in the form of just checking if you can identify shellcode and use the GDB debugger; pretty trivial to get past. If this poses any problems then looking into the SecurityTube Assembly Expert would be very helpful.

The lab contains the instructional videos and PDF that covers the course content.  It splits things up into five areas: Web application issues, backdooring executables, ASLR and egghunters, fuzzing with Spike for zero days, and finally attacking the networking infrastructure.

Unlike the OSCP, there are only a couple machines available to you as all the exploit development will be done on your Kali, Vista, or Windows Server box and all the applications you deal with will reside on one of them (the course uses the old BackTrack distro but I had no issues using the current Kali image).

Most modules you go through will be consumable without too much issue with module 8 being the most difficult and probably where you'll spend most of your time due to learning about creating exploits where there are tight restrictions as to what will work for a successful exploit.

I spent probably about a week to get through all the content the first time.  I then repeated it several times and automated some of it with python to help understand the material.  I also spent a decent amount of time on external sites teaching related material to help understand it even better.

## The OSCE Exam
The exam is a 48 hour block of time given to complete the requirements.  The objectives line up somewhat close to the course content but not entirely.  For certain areas in exploit development I ended up learning more during the exam than I did going through the course content (and I went through that content 3-4 times over).

In hindsight, to succeed in the more difficult parts of the exam you'll need to do research and learn a bit more in each area than what is directly in the course. Thinking a bit out of the box and not getting stuck on just what is shown in the lab content helps too.

On my first attempt and completed everything except one little thing (on the harder machine) that led to not passing.  I knew what I needed to do but just couldn't get it to work. A day after the exam I figured out what I was trying to do and rescheduled less than a week out and passed it.

## Final Thoughts
This was the most enjoyable course I've taken with Offensive Security due to the subject matter lining up with my core interests.  The course gives you a guideline of content to learn and then its up to you to do additional research in each area.  If exploit development is of interest to you and you haven't done much of it yet this gives a good foundation to start learning more current content.  

Prior to this course I tried to learn and understand present day exploit topics and much of it was foreign and hard to understand (from a hands-on practical stance); after this course it all seems more "common sense" now and I'm picking it up much quicker. In that sense, this may be one of the better ways to jump start your exploit research or reversing career.
