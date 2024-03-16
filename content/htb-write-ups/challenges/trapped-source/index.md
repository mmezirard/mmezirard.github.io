+++
title = "Trapped Source"
date = "2024-03-16"
description = "This is a very easy Web challenge."
[extra]
cover = "cover.svg"
toc = true
+++

# Information

**Difficulty**: Very easy

**Category**: Web

**Release date**: 2023-05-23

**Created by**: [makelaris](https://app.hackthebox.com/users/107)

**Description**: Intergalactic Ministry of Spies tested Pandora's movement and
intelligence abilities. She found herself locked in a room with no apparent
means of escape. Her task was to unlock the door and make her way out. Can you
help her in opening the door?

# Setup

I'll complete this challenge using a Kali Linux VM.

# Exploration

Let's browse to `http://94.237.49.182:44243/`:

![Web homepage](web-homepage.png)

We're presented with a vault.

# Source code review

If we check the source code of the web page, we find this `<script>` tag:

```html
<script>
    window.CONFIG = window.CONFIG || {
        buildNumber: "v20190816",
        debug: false,
        modelName: "Valencia",
        correctPin: "4895",
    }
</script>
```

The correct PIN is written in cleartext: it's `4895`!

# Exploration

Back to the website, let's enter this PIN.

![Web homepage PIN entered](web-homepage-pin-entered.png)

It fails.

# Source code review

Back to the source code of the website, we find a link to `/script.js`.

```js
currentPin = [];

const checkPin = () => {
    pin = currentPin.join("");

    if (CONFIG.correctPin == pin) {
        fetch("/flag", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                pin: CONFIG.correctPin,
            }),
        })
            .then((data) => data.json())
            .then((res) => {
                $(".lockStatus").css("font-size", "8px");
                $(".lockStatus").text(res.message);
            });
        return;
    }

    $(".lockStatus").text("INVALID!");
    setTimeout(() => {
        reset();
    }, 3000);
};

const unlock = (pin) => {
    currentPin.push(pin);

    if (currentPin.length > 4) return;

    $(".lockStatus").text(currentPin.join(" "));
};

const reset = () => {
    currentPin.length = 0;
    $(".lockStatus").css("font-size", "x-large");

    $(".lockStatus").text("LOCKED");
};
```

The `checkPin` function is the most interesting here. If the correct PIN is
entered, a POST request is sent to `/flag` with the JSON data:

```json
{
    "pin":"4985"
}
```

Since the `currentPin` variable is never updated, the correct PIN is never
entered. Therefore, let's send ourselves the POST request to the `/flag`
endpoint:

```sh
❯ curl -s -H "Content-Type: application/json" "http://94.237.49.182:44243/flag" -X "POST" -d '{"pin": "4985"}' | jq "." --indent "4"
```

```
{
    "message": "HTB{vi3w_cli13nt_s0urc3_S3cr3ts!}\n"
}
```

We got the flag!

In fact, we specify any PIN we want, it's not even checked by the backend.

# Afterwords

![Success](success.png)

That's it for this box! 🎉

I rated this challenge as 'Piece of cake'. It just required to read the source
code of the page really, although it contained a bait to mislead us.

Thanks for reading!
