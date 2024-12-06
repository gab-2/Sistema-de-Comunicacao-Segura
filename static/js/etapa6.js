// Variáveis de controle
let isDecrypting = false;

// Função para mostrar ou esconder a animação de descriptografia
const showDecryptAnimation = (show) => {
    const animationDiv = document.getElementById("decrypt-animation");
    if (animationDiv) {
        animationDiv.style.display = show ? "flex" : "none";
    }
};

// Função para mostrar ou esconder a mensagem de sucesso
const showDecryptSuccess = (show) => {
    const successDiv = document.getElementById("decrypt-success");
    if (successDiv) {
        successDiv.style.display = show ? "flex" : "none";
    }
};

// Função para atualizar o texto informativo
const updateInfoText = (text) => {
    const infoTextDiv = document.getElementById("info-text");
    if (infoTextDiv) {
        infoTextDiv.innerHTML = text;
    }
};

// Função para realizar a descriptografia (simulação)
const startDecrypt = () => {
    if (isDecrypting) return;

    // Iniciar a animação
    isDecrypting = true;
    showDecryptAnimation(true);
    updateInfoText("Descriptografando... Por favor, aguarde.");

    // Simulação de delay de descriptografia
    setTimeout(() => {
        showDecryptAnimation(false);
        showDecryptSuccess(true);
        updateInfoText("Descriptografia concluída com sucesso!");
        isDecrypting = false;
    }, 5000);
};

// Evento para o botão "Iniciar Descriptografia"
document.getElementById("decrypt-button").addEventListener("click", startDecrypt);

// Evento para o botão "Anterior"
document.getElementById("previous-button").addEventListener("click", () => {
    window.location.href = "/etapa5";  // Redireciona para a etapa 5
});
