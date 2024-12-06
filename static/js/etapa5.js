// Seletores de Elementos
const sendPackageButton = document.getElementById("send-package-button");
const simulationContainer = document.getElementById("simulation-container");
const nextButton = document.getElementById("next-button");
const previousButton = document.getElementById("previous-button");

// Botão "Enviar Pacote"
sendPackageButton.addEventListener("click", () => {
    // Simular o envio
    sendPackageButton.disabled = true;
    simulationContainer.style.display = "flex";

    // Simulação de envio (exemplo de 2 segundos)
    setTimeout(() => {
        alert("Pacote enviado com sucesso!");
        nextButton.disabled = false; // Habilita o botão "Próximo"
    }, 2000);
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/etapa4"; // Redireciona para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa6"; // Redireciona para a próxima etapa
});
