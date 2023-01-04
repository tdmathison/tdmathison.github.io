---
title: OSCP Review
date: 2017-07-14 12:00:00 -0700
categories: [Blogging, Offensive-Security]
tags: [offensive-security, oscp, penetration-testing, hacking]
---

## Background
I have been a developer for longer than I can remember (over 20 years), interested in hacking and the security side of things for much of it as well.  However, it wasn't until relatively recently (3 or so years) that I started to consider an actual pivot away from every day development into more of a security focused type of role.  It didn't take too long to realize that the Offensive Security training was what I was looking for.

Coming into this as someone that was primarily a developer was probably harder than someone coming in as a network administrator.  I found very quickly that my understanding of networking and protocols was not up-to-speed and that I had quite a bit of learning to do.  I had only mildly played with Kali Linux as well but had been using Linux regularly for 5 or so years (and now as a daily driver).

At work, I kept driving towards doing more security related development work and with some persistence and good timing a security focused development team was developed that I now work in.  One of my colleagues and I decided it was time to sign up for the OSCP and go through this experience.

## The OSCP Lab
I signed up for the OSCP training with two months of lab time.  I read through the syllabus over and over and started reading about many of the tools before I ended up starting the lab.  Once I signed up I pretty much watched all of the videos straight through in a single sitting.  Throughout the following month I went back several times to watch some of the video sections over. The majority of the time was spent in the lab attempting to find vulnerabilities in the systems on the public network.

Things are structured where once you VPN in you have access to the public network with quite a few machines in it.  Upon compromising certain machines you will find some that are connected to other networks in which you can pivot to.

It took quite a bit of time learning how to effectively do enumeration and I didn't realize quite how important it was to get this right until later. Developing a good systematic method to enumerate and log findings is a key skill to develop.  Learning how to gather all information first before diving deep into any one of them is critical.  Initially, I would find the first thing that looked promising and focus in on it hard ignoring everything else around it not realizing that there may have been some other low-hanging fruit right next to it.

About a month and a half through the lab time I pretty much knew I was not there yet.  I had compromised around 30 machines, one of which was among the harder machines called ‘pain’. I went all the way to the end of the two month thinking I would take the test right at the end.  The lab time ended, I had a little break and ended up scheduling the exam around a month later.

## The OSCP Exam
The exam is a 24 hour performance based test where you VPN in and can either hack through the machines on the exam network or you can’t.  Waiting to take the exam was a mistake and I think I had burnt myself out as I was basically doing nothing but 14 or so hours a day (more on weekends) for two months straight. I finally took the test and only compromised two machines fully with a low priv on a third and did not pass.  It was upsetting but also not unexpected; I usually don't fail at things I devote myself to so this was not normal.

After a little break of a couple months I got more lab time, another two months.  I started by going through and re-hacking the machines I previously did and the compromises did go much quicker this time around and in short time I had re-compromised over 20 of them and by around a month in was at around 45 machines compromised (including sufferance and humble (humble was figured out at the very end and taught a few lessons that I won't soon forget)).

## Persevered until success
I took my second attempt while I still had lab time left as I did not want to have a break like on the first exam.  This time around I had a better understanding of the format of the test and what to expect.  I did a little better on the exam but again got stuck on a particular machine where I knew it was either I escalated to pass or it was a fail; again, it got the better of me and I was In the 18+ hour point where it was hard to concentrate and I was unable to accomplish this task.

On my third attempt I prepared based on some of my weak points and knew which machines to attack and in which order.  Within the first two hours and had two machines down, in another 5 hours had escalated a third and a little later had a low privilege shell on a fourth.  Things were going well and this all was happening before my mind turned to mush and I couldn’t think straight. I succeeded on this attempt and was able to get enough points to finally pass the exam.

This whole process from signing up to being successful took me about 6 months due to a two month break in between my two lab sessions. I put more hours into studying this content than anything else I’ve ever done; seriously, I probably had spent over 700+ hours learning and practicing in this 6 month period of time.

## Documentation
During this time I signed up for a personal Confluence account and have been building out my own notes on every tool and process I learned up to this point.

As I struggled through using different tools and learned the correct syntax and quirks of a tool I would document it.  I now have quite a large penetration testing confluence site that has a wealth of information in it for me to reference and continue adding to. This was a smart move and I pretty much always have it up for reference and am updating it as I continue to learn more things.

Whenever you make a breakthrough or get through a struggle you should document how you did it; you will end up running into it again and it is extremely helpful to return to accurate notes of how you did it the last time.

## Easiest Part
Enjoying the subject matter made a certain amount of things easier for sure. Certainly it helped me get through a lot of the struggles and not give up. Working in Linux was much easier for me than perhaps others and I use Arch Linux as my daily driver. Even being an everyday Linux user I came out the other end even more familiar than I was before.

The other part that was much easier for me was exploit development.  I used to program in assembly and C/C++ and so this was a strong point for me.  Compiling C code and writing and running Python exploits was generally very quick and any issues that came up were often very easy for me to resolve.

## Hardest Part
The Windows side of things was generally a little harder for me than Linux.  Probably not for the reason you would think though.  I have quite a bit of familiarity with both operating systems but Windows is just a pain to work with compared to Linux.  Trying to do anything on a Windows box is like pulling teeth and it is frustrating.

Through the process I have started picking up some better enumeration scripts and have created some of my own to assist in this. Usually the issues are pretty easy to locate but often the preparation and execution of the exploit takes longer than on a Linux based machine. One of the things that may be very helpful is to list out all known exploits for CVE's against Windows and have pre-compiled exploits for them ready to go.  I had so many instances where I needed to compile a Windows exploit and it was very time consuming.  In some cases, you need to compile a python script as a Windows binary as well so having all these environments ready is important when the clock is ticking.

Spinning up on the network security side of things was harder than the development side.  I have now become much more proficient in networking related topics through the hands on knowledge I have gained during my lab time.

Stress management was something I also struggled with from time to time.  I had high expectations of myself and not performing to the level I thought I initially would affected me.  It took me awhile to realize that this is normal and it actually meant that I am pushing myself to my limits which was a good thing.

## Final Thoughts
This was the hardest exam I have ever taken in my life.  It was often an emotional roller coaster for a variety of reasons over the course of the time doing it. This benefits of this course are in what you learn along the way with passing the exam being the bonus it all culminates with.  Even if I didn’t end up getting the certification I still would be in a far better position knowledge-wise than before.

I have acquired a lot of certifications through my years but none of them really tested whether you could actually "DO" and "APPLY" knowledge like the OSCP exam; going down this route was one of the best choices I have made in my professional career and is setting a path for where I want to go next.

My plan going forward is to start uploading some of my projects and scripts to my github account, starting blogging now and then, tweet and little, and finally prepare for the OSCE.  In preparation, I have gathered some information from peers that going through the SLAE course is a good idea so I will do that first and then start tackling the OSCE at the end of the year and make it my 2018 goal.
