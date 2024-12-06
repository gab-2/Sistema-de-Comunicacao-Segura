// Seletores de Elementos
const protectAESButton = document.getElementById("protect-aes-key");
const comparisonContainer = document.getElementById("comparison-container");
const processResults = document.getElementById("process-results");
const successMessage = document.getElementById("success-message");
const previousButton = document.getElementById("previous-button");
const nextButton = document.getElementById("next-button");

// Botão "Proteger Chave Simétrica"
protectAESButton.addEventListener("click", () => {
    // Simulação do processo
    protectAESButton.disabled = true;
    comparisonContainer.style.display = "flex";

    setTimeout(() => {
        processResults.style.display = "flex";
        successMessage.style.display = "block";
        nextButton.disabled = false; // Habilita o botão "Próximo"
    }, 2000); // Simulação de 2 segundos
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/etapa3"; // Redireciona para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa5"; // Redireciona para a próxima etapa
});
