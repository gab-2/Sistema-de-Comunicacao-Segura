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
const showDecryptSuccess = (show, message = "") => {
    const successDiv = document.getElementById("decrypt-success");
    if (successDiv) {
        successDiv.style.display = show ? "flex" : "none";
        successDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
    }
};

// Função para atualizar o texto informativo
const updateInfoText = (text) => {
    const infoTextDiv = document.getElementById("info-text");
    if (infoTextDiv) {
        infoTextDiv.innerHTML = text;
    }
};

// Função para realizar a descriptografia
const startDecrypt = async () => {
    if (isDecrypting) return;

    const privateKeyFile = document.getElementById("private-key-file")?.files[0];
    const encryptedFile = document.getElementById("encrypted-file-input")?.files[0];

    if (!privateKeyFile || !encryptedFile) {
        alert("Ambos os arquivos são necessários: chave privada e arquivo criptografado.");
        return;
    }

    const formData = new FormData();
    formData.append("private_key_file", privateKeyFile);
    formData.append("encrypted_file", encryptedFile);

    showDecryptAnimation(true);
    updateInfoText("Descriptografando... Por favor, aguarde.");

    try {
        const response = await fetch("/decrypt_file", {
            method: "POST",
            body: formData,
        });

        showDecryptAnimation(false);

        if (response.ok) {
            const data = await response.json();
            showDecryptSuccess(true, "Arquivo descriptografado com sucesso!");
            updateInfoText("Descriptografia concluída com sucesso!");
            document.getElementById("decrypt-success").innerHTML += `<br><a href="${data.decrypted_file}" class="btn" download>Baixar Arquivo</a>`;
        } else {
            const errorData = await response.json();
            console.error("Erro do servidor:", errorData.error);
            alert(`Erro durante a descriptografia: ${errorData.error}`);
            updateInfoText("Erro durante a descriptografia. Tente novamente.");
        }
    } catch (error) {
        console.error("Erro ao conectar ao servidor:", error);
        alert("Erro ao conectar ao servidor. Tente novamente.");
        updateInfoText("Erro ao conectar ao servidor.");
    } finally {
        isDecrypting = false;
    }
};

// Evento para o botão "Iniciar Descriptografia"
const decryptButton = document.getElementById("decrypt-button");
if (decryptButton) {
    decryptButton.addEventListener("click", startDecrypt);
} else {
    console.error("Botão de descriptografia não encontrado.");
}

// Evento para o botão "Anterior"
const previousButton = document.getElementById("previous-button");
if (previousButton) {
    previousButton.addEventListener("click", () => {
        window.location.href = "/etapa5"; // Redireciona para a etapa 5
    });
} else {
    console.error("Botão Anterior não encontrado.");
}

// Função para abrir e fechar o modal (se necessário no fluxo)
const showModal = (message) => {
    const modal = document.getElementById("modal");
    const modalMessage = document.getElementById("modal-message");

    if (modal && modalMessage) {
        modalMessage.textContent = message;
        modal.style.display = "block";

        const closeModal = document.getElementById("close-modal");
        if (closeModal) {
            closeModal.addEventListener("click", () => {
                modal.style.display = "none";
            });
        }
    }
};

// Adicionar evento para fechar o modal ao clicar fora dele
window.onclick = (event) => {
    const modal = document.getElementById("modal");
    if (event.target === modal) {
        modal.style.display = "none";
    }
};
