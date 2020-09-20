---
title: "hackthebox.eu Invite Code"
date: 2020-09-19 15:09:28 -0400
categories: jekyll update
---
Today, we will go over how to obtain the invite code in hackthebox.eu and register.

Hack The Box is an online platform allowing you to test your penetration testing skills and exchange ideas and methodologies with thousands of people in the security field.

For some reason, hackthebox wants us to obtain some kind of invite code by ourselves in order to register.
![hackthebox.eu front page](https://raw.githubusercontent.com/079035/079035.github.io/master/Capture.PNG)

If we click on "Join Now", the following page appears:
![Invite challenge](https://raw.githubusercontent.com/079035/079035.github.io/master/images/Capture.PNG)

Let's click on "Click Here!" and we get:

```You could check the console...```

```Ctrl + Shift + i``` will switch to developer mode.
![Developer Mode](https://raw.githubusercontent.com/079035/079035.github.io/master/images/DM.PNG "Developer mode")
We go to the console and see this:
![Console](https://raw.githubusercontent.com/079035/079035.github.io/master/images/skull.PNG)

```This page loads an interesting javascript file. See if you can find it :)```

In the elements pane, we can find /js/inviteapi.min.js, and we access it.
https://www.hackthebox.eu/js/inviteapi.min.js:
```
//This javascript code looks strange...is it obfuscated???

eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0 3(){$.4({5:"6",7:"8",9:\'/b/c/d/e/f\',g:0(a){1.2(a)},h:0(a){1.2(a)}})}',18,18,'function|console|log|makeInviteCode|ajax|type|POST|dataType|json|url||api|invite|how|to|generate|success|error'.split('|'),0,{}))
```

If we scroll down to the end, we can find ```makeInviteCode``` function.  

We go back to www.hackthebox.eu/invite, go to console, and enter makeInviteCode().
![makeInviteCode](https://raw.githubusercontent.com/079035/079035.github.io/master/images/makeInviteCode.PNG)

result:
```
{0: 200, success: 1, data: {…}, hint: "Data is encrypted … We should probably check the encryption type in order to decrypt it…"}
0: 200
data:
data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/vaivgr/trarengr"
enctype: "ROT13"
__proto__: Object
hint: "Data is encrypted … We should probably check the encryption type in order to decrypt it…"
success: 1
__proto__: Object
```

It says that the data is encrypted with ROT13.
We go to rot13.com and decrypt it:

![ROT13](https://raw.githubusercontent.com/079035/079035.github.io/master/images/rot.PNG)

Time to make some POST requests.
We normally use [cURL] to make **GET** and **POST** requests.

In your terminal: type: ```curl -XPOST https://www.hackthwebox.eu/api/invite/generate```

You'll get something like this:
```
{"success":1,"data":{"code":"V0ZCRlUtVENYRVItVlFRVFktUE1TVUwtQ0hFUkQ=","format":"encoded"},"0":200}
```
You should familiarize with the upper format which is BASE64, they are normally consisted with capital letters, numbers, and few "=" sign at the end.

We decode the data by going to https://www.base64decode.org/.

![Base64 decode](https://raw.githubusercontent.com/079035/079035.github.io/master/images/base64.PNG)
```WFBFU-TCXER-VQQTY-PMSUL-CHERD```

That is our invite code(Yours might look slightly different).

Thank you,

079

[cURL]: ("https://en.wikipedia.org/wiki/CURL")
