## More datapoints

Datapoint Examples:

- regular details
- hosted domain (domain.forgithub.com)
- usage stats
- github oauth client sign-ins
- openapi summary
- SPEC.md
- HACKERNEWS.md (what topics are relevant here?)
- screenshot of homepage
- cost
- last deployment(s)
- size (specifically, number of tokens)
- links to useful views
- links to take agentic actions
- category stack (generated with LLM)
- actions summary / success
- logo of deployment provider

## Listening

❗️ We need a way to nicely request and store an access_token for watching from the dashboard.

1. Actually subscribe to watching all repos upon login (via a waituntil+scheduled api call).
2. Ensure per user I know the source (where/when they logged in)
3. Ensure the watching all lands in cache
4. Watch also triggers calculating all repo stuff, so we end up with a file of all repos + calcs that is refreshed each time something changes. 🐐

- make it listen and upate
- track anyones commit events and accumulate their 'changes'
- track all actions too and show them in dashboard. key for claudeflair

## `/owner/dashboard.json`

Improve `dashboard.forgithub.com/dashboard.json`:

- Returns KV value immediately (or loads if not yet or `?refresh=true`)
- Calls `waitUntil` that calls queue to fetch from `join` if KV >1h old or if there was a `?refresh=true`
- Has README.md, CHANGELOG.md, SPEC.md, TODO.md, ADR.md, size, and openapiSummary
- Has `context: {id:string,title:string,url:string,description:string}[]` which can be used for chat (redirect to `chat.forgithub.com?context=https://dashboard.forgithub.com/dashboard.json&id=xxx`)

Does this just for all repos from the last 30 days (for now) to prevent ratelimit trouble.

OpenAPI for `dashboard.json` and `dashboard.md`

## `/[owner]/dashboard.md?focus=[datapoint]`

✅ Write simple function that just nicely renders it as markdown.

If focus is provided, will also show one of the long datapoints (README.md and other pages)

Be sure to do one more iteration on chat (nav and some bugs) - then ask people to test to use this - and then prepare a 'announching uithub chat' post.

## `/[owner]/dashboard.html` UI

- ✅ link to show raw data
- ✅ clear buttons linking to useful things like uithub, github, website, forgithub (other tools)
- at the top, select what to view in the right pane
- at the top, add search that matches on full_name
- show repo card with screenshot on the left, pane at the right that renders a datapoint such as README.md, CHANGELOG.md, SPEC.md, TODO.md, ADR.md, size, and openapiSummary

## https://dashboard.forgithub.com/[owner]

We need to use the same datapoint but render a more exploration friendly dashboard intended to understand what someone does. Can use the same `dashboard.json/md` api!

# Queue improvements

After push:

- call for https://diagram.forgithub.com/owner/repo/image.png?max-age=0
- call for https://size.forgithub.com/owner/repo

After deployment (1 minute after)

- call for https://quickog.com/screenshot/{url} (only insert if 200)

# blog

Write a supercool blogpost layout out the idea of 'validation looped coding'. put this on wilmake.com and other pages, ensure CTA is sponsorship, and push this to hackernews. go all in on this article going viral and collecting signups. every page from now that I release should have a sign-in button to sign-in with github, after which i know much more about the person.

# cycle

After all of the above functions as desired, the dashboard can become the home for initiating agentic work. It's to be a goto place to see how you are doing and what's happening with your work.

- patch
- actions
- cycle!!! overview of cycles from dashboard 🐐🔥

# Create powerful worker-creator guide and chat

As a simple first demonstration of the product, create `uithub.chat` which simply proxies to chatcompletions.com/chat/completions but with key of R1, and charges the price needed. I already had docs.uithub.com/upstash-chat. Just use that one. Make it easy to put guides in context using select-boxes.

- DO for schedule, do for queue, do for kv/sql... document DOs with some very good examples and how it works in very few tokens
- create a very good prompt that generates all needed files for a worker besides the template from some simple natural language
- include the sponsorflare.ts
- put this prompt at a URL, easy to find.

Release uithub.chat API and UX with limit to -1.00 balance after signup (redirect oauth after hitting submit with prompt stuck in localstorage)

THIS IS WORTH A BIG AMOUNT OF LIKES IF I SHARE THE PROMPT. OR JUST CHAT?
