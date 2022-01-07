window.addEventListener('load', function(a) {
  a.preventDefault();//prevent from reloading

  fetch('/task', {

    method: 'get', 
    cache: 'no-cache',
    credentials: 'same-origin', 
    headers: {
      'Content-Type': 'application/json'
    },
    redirect: 'follow', 
    referrerPolicy: 'no-referrer', 
  }).then(function(response) {
    return response.text();
  }).then(function(text) {
    console.log(text); //should really actually output it to the HTML as a table; this isn't the section I (G.E.) had been planned to do so I'm not going to focus on fixing it;
  }).catch(function(error) {
    console.error(error);
  })
});