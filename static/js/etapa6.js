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

    // Obter os dados necessários
    const privateKey = document.getElementById("private-key")?.value?.trim(); // Campo de chave privada
    const encryptedFile = document.getElementById("encrypted-file-input")?.files[0]; // Arquivo criptografado
    const signatureFile = document.getElementById("signature-file-input")?.files[0]; // Arquivo de assinatura

    // Verificar se todos os dados foram preenchidos
    if (!privateKey) {
        alert("Por favor, insira a chave privada.");
        return;
    }

    if (!encryptedFile) {
        alert("Por favor, selecione o arquivo criptografado.");
        return;
    }

    if (!signatureFile) {
        alert("Por favor, selecione o arquivo de assinatura.");
        return;
    }

    console.log("Iniciando descriptografia com os seguintes dados:");
    console.log("Chave Privada:", privateKey);
    console.log("Arquivo Criptografado:", encryptedFile);
    console.log("Arquivo de Assinatura:", signatureFile);

    // Iniciar a animação
    isDecrypting = true;
    showDecryptAnimation(true);
    updateInfoText("Descriptografando... Por favor, aguarde.");

    // Criar o FormData para envio ao backend
    const formData = new FormData();
    formData.append("private_key_file", new Blob([privateKey], { type: "text/plain" }));
    formData.append("encrypted_file", encryptedFile);
    formData.append("signature_file", signatureFile);

    try {
        // Fazer a requisição para o backend
        const response = await fetch("/decrypt_file", {
            method: "POST",
            body: formData,
        });

        const data = await response.json();

        // Parar a animação
        showDecryptAnimation(false);

        if (response.ok) {
            // Exibir mensagem de sucesso
            showDecryptSuccess(true, "Arquivo descriptografado com sucesso!");
            updateInfoText("Descriptografia concluída com sucesso!");
        } else {
            // Exibir mensagem de erro
            alert(`Erro: ${data.error}`);
            updateInfoText("Erro durante a descriptografia.");
        }
    } catch (error) {
        console.error("Erro durante a descriptografia:", error);
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
