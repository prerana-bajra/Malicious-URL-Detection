// popup.js

// Function to handle prediction
function predict() {
  console.log('Predict function called'); // Log to console to verify function execution
  var url = document.getElementById('urlInput').value;
  
  // Show loading text or spinner
  document.getElementById('loading').style.display = 'flex';
  
  fetch('http://localhost:5000/predict', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({url: url})
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    // Hide loading text or spinner
    document.getElementById('loading').style.display = 'none';
    
    // Display result in HTML
    var resultElement = document.getElementById('result');
    resultElement.innerHTML = ''; // Clear previous result
    
    // Determine the color based on the prediction result
    var color = data.result_str === "URL IS SAFE!" ? "green" : "red";
    
    // Create a div element for the result
    var resultDiv = document.createElement('div');
    resultDiv.textContent = data.result_str;
    resultDiv.classList.add('result-card');
    resultDiv.style.backgroundColor = color;
    
    // Append the result div to the result element
    resultElement.appendChild(resultDiv);
    
    // Display similar URLs if available
    if (data.google_results.length > 0) {
      var similarUrls = data.google_results;
      var similarUrlsContainer = document.createElement('div');
      
      similarUrls.forEach(function(url) {
        // Create a card for each similar URL
        var similarUrlCard = document.createElement('div');
        similarUrlCard.classList.add('similar-card');
        similarUrlCard.innerHTML = '<a href="' + url + '" target="_blank">' + url + '</a>';
        similarUrlsContainer.appendChild(similarUrlCard);
      });
      
      // Append the similar URLs container to the result element
      resultElement.appendChild(similarUrlsContainer);
    }
  })
  .catch(error => {
    console.error('Error:', error);
    // Hide loading text or spinner
    document.getElementById('loading').style.display = 'none';
    // Display error message
    document.getElementById('result').innerText = 'Error: Prediction failed. Please try again later.';
  });
}

// Add event listener for the "Predict" button click event
document.addEventListener('DOMContentLoaded', function() {
  var predictButton = document.getElementById('predictButton');
  if (predictButton) {
    predictButton.addEventListener('click', predict);
  } else {
    console.error('Predict button not found');
  }
});
