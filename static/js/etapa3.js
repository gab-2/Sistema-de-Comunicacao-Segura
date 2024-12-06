// Seletores de Elementos
const previousButton = document.getElementById("previous-button");
const nextButton = document.getElementById("next-button");
const startProcessButton = document.getElementById("start-process");
const processResults = document.getElementById("process-results");
const successMessage = document.getElementById("success-message");
const animationContainer = document.getElementById("animation-container");

// Botão "Iniciar Processo"
startProcessButton.addEventListener("click", () => {
    // Exibir a animação do processo
    startProcessButton.disabled = true;
    animationContainer.style.display = "block";

    // Simulação do progresso com a animação
    const progressFill = document.querySelector(".progress-fill");
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 10;
        progressFill.style.width = `${progress}%`;

        if (progress >= 100) {
            clearInterval(progressInterval);
            animationContainer.style.display = "none"; // Esconde a animação
            processResults.style.display = "flex"; // Exibe os resultados
            successMessage.style.display = "block"; // Mostra a mensagem de sucesso
            nextButton.disabled = false; // Habilita o botão "Próximo"
        }
    }, 200); // Atualiza a cada 200ms
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/etapa2"; // Redireciona para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa4"; // Redireciona para a próxima etapa
});
