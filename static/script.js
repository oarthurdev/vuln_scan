function startLoading() {
  var progressBar = document.getElementById('progress');
  var width = 0;
  
  // Registra o evento load para detectar quando a resposta foi recebida
  window.addEventListener('load', function() {
    width = 100;
    progressBar.style.width = width + '%';
  });
  
  var interval = setInterval(function() {
    // Incrementa o progresso gradualmente até 99%
    if (width < 99) {
      width++;
      progressBar.style.width = width + '%';
    }
  }, 10);
}