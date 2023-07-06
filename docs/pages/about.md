---
layout: page
title: About
permalink: /about/
weight: 3
---

# **About Me**

Hi I am **{{ site.author.name }}** :wave:,<br>
I am working on getting better at CTFs, software engineering, and coding in general.<br>
I tend of focus on pwnable challenges, and I try to expose myself to a various types of pwn challenges (userspace, kernel, web browser, smart contract, etc.)
so that I can decide which area of pwn I can specialize on.<br>
I am also interested in quantitative finance and machine learning:smile:.<br>
Thank you for your interest.

<div class="row">
{% include about/skills.html title="Programming Skills" source=site.data.programming-skills %}
{% include about/skills.html title="Other Skills" source=site.data.other-skills %}
</div>

<div class="row">
{% include about/timeline.html %}
</div>
