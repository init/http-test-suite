Web server test suite
=====================

Implement a Web server in the programming language of your choice. Libraries for helping manage TCP socket connections *may* be used (libevent allowed). Libraries that implement any part of HTTP or multiprocessing model *must not* be used.

## Requirements ##

* Respond to `GET` with status code in `{200,404}`
* **Bonus:** Respond to `HEAD` with status code in `{200,404}`
* Respond to all other request methods with status code `405`
* Directory index file name `index.html`
* Respond to requests for `/<file>.html` with the contents of `DOCUMENT_ROOT/<file>.html`
* Requests for `/<directory>/` should be interpreted as requests for `DOCUMENT_ROOT/<directory>/index.html`
* Respond with the following header fields for all requests:
  * `Server`
  * `Date`
  * `Connection`
* Respond with the following additional header fields for all `200` responses to `GET` and `HEAD` requests:
  * `Content-Length`
  * `Content-Type`
* Respond with correct `Content-Type` for `.html, .css, js, jpg, .jpeg, .png, .gif, .swf`
* Respond to percent-encoding URLs
* No security vulnerabilities!
* **Bonus:** Correctly serve a 2GB+ file

## Testing environment ##

* `httptest` folder from `http-test-suite` repository should be copied into `DOCUMENT_ROOT`
* Your HTTP server should listen `localhost:80`

## Success criteria ##

* Must pass test suite: `./httptest.py`
* `http://localhost/httptest/wikipedia_russia.html` must been shown correctly in browser
* **Bonus:** Lowest-latency response (tested using `ab`, ApacheBench) in the following fashion: `ab -n 50000 -c 100 -r http://localhost:8080/`

## Resources ##

* http://www.w3.org/Protocols/rfc2616/rfc2616.html
* http://www.kegel.com/c10k.html
* http://www.aosabook.org/en/nginx.html
* http://www.slideshare.net/joshzhu/nginx-internals

