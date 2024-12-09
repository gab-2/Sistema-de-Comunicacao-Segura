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
    const privateKeyFile = document.getElementById("private-key-file-input")?.files[0]; // Arquivo da chave privada
    const encryptedFile = document.getElementById("encrypted-file-input")?.files[0]; // Arquivo criptografado

    if (!privateKeyFile) {
        alert("Por favor, selecione o arquivo da chave privada.");
        return;
    }

    if (!encryptedFile) {
        alert("Por favor, selecione o arquivo criptografado.");
        return;
    }

    console.log("Arquivo da Chave Privada:", privateKeyFile);
    console.log("Arquivo Criptografado:", encryptedFile);

    const formData = new FormData();
    formData.append("private_key_file", privateKeyFile);
    formData.append("encrypted_file", encryptedFile);

    try {
        const response = await fetch("/decrypt_file", {
            method: "POST",
            body: formData,
        });
        const data = await response.json();

        if (response.ok) {
            alert("Descriptografia concluída com sucesso!");
        } else {
            console.error(data.error);
            alert(`Erro durante a descriptografia: ${data.error}`);
        }
    } catch (error) {
        console.error("Erro ao enviar a requisição:", error);
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
