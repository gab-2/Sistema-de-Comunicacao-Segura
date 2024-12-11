// Seletores de Elementos
const sendPackageButton = document.getElementById("send-package-button");
const statusMessage = document.getElementById("status-message");
const downloadLinks = document.getElementById("download-links");
const downloadZipLink = document.getElementById("download-zip");
const nextButton = document.getElementById("next-button");
const previousButton = document.getElementById("previous-button");

// Função para atualizar a mensagem de status
function updateStatusMessage(color, message) {
    if (statusMessage) {
        statusMessage.innerHTML = `<p style="color: ${color};">${message}</p>`;
    }
    console.log(`Status atualizado: ${message}`); // Log adicional
}

// Função para exibir o link de download do pacote ZIP
function showDownloadLink(zipUrl) {
    if (downloadLinks && downloadZipLink) {
        downloadZipLink.href = zipUrl; // Atualiza o link do ZIP
        downloadLinks.style.display = "block"; // Exibe o link de download
        console.log(`Link de download atualizado para: ${zipUrl}`); // Log adicional
    } else {
        console.error("Elementos de download não encontrados no HTML.");
    }
}

// Evento de clique no botão "Enviar Pacote"
sendPackageButton.addEventListener("click", async () => {
    sendPackageButton.disabled = true; // Desativa o botão para evitar cliques duplicados

    try {
        updateStatusMessage("blue", "Enviando pacote...");

        const formData = new FormData();

        // Buscando e validando arquivos necessários
        console.log("Buscando arquivos necessários...");
        const encryptedFile = await fetch("/download/encrypted_file")
            .then(res => {
                if (!res.ok) throw new Error("Erro ao baixar o arquivo criptografado.");
                return res.blob();
            })
            .catch(err => {
                throw new Error(`Falha ao obter o arquivo criptografado: ${err.message}`);
            });
        console.log("Arquivo criptografado baixado com sucesso.");

        const signatureFile = await fetch("/download/signed_file")
            .then(res => {
                if (!res.ok) throw new Error("Erro ao baixar o arquivo de assinatura.");
                return res.blob();
            })
            .catch(err => {
                throw new Error(`Falha ao obter o arquivo de assinatura: ${err.message}`);
            });
        console.log("Arquivo de assinatura baixado com sucesso.");

        const protectedKeyFile = await fetch("/download/protected_aes_key.pem")
            .then(res => {
                if (!res.ok) throw new Error("Erro ao baixar a chave protegida.");
                return res.blob();
            })
            .catch(err => {
                throw new Error(`Falha ao obter a chave protegida: ${err.message}`);
            });
        console.log("Chave protegida baixada com sucesso.");

        // Adiciona arquivos ao FormData
        formData.append("encrypted_file", new File([encryptedFile], "encrypted_file_name"));
        formData.append("signature_file", new File([signatureFile], "signed_file_name"));
        formData.append("protected_aes_key", new File([protectedKeyFile], "protected_aes_key.pem"));

        console.log("Arquivos adicionados ao FormData com sucesso.");

        // Faz a requisição ao backend para criar o ZIP
        const response = await fetch("/send_package", {
            method: "POST",
            body: formData,
        });

        console.log("Requisição ao backend enviada.");
        const result = await response.json();

        if (response.ok) {
            updateStatusMessage("green", "Pacote enviado com sucesso!");
            console.log("Pacote enviado com sucesso:", result);

            // Mostra o link para baixar o arquivo ZIP
            showDownloadLink("/download/package_zip");

            nextButton.disabled = false; // Habilita o botão "Próximo"
        } else {
            throw new Error(result.error || "Erro desconhecido ao enviar o pacote.");
        }
    } catch (error) {
        updateStatusMessage("red", `Erro: ${error.message}`);
        console.error("Erro durante o envio do pacote:", error);
    } finally {
        sendPackageButton.disabled = false; // Reativa o botão após o término
    }
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    console.log("Redirecionando para a etapa anterior...");
    window.location.href = "/etapa4";
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    console.log("Redirecionando para a próxima etapa...");
    window.location.href = "/etapa6";
});

// Logs adicionais para rastrear o estado inicial
console.log("JS da etapa 5 carregado com sucesso.");
console.log("Elementos identificados:", {
    sendPackageButton,
    statusMessage,
    downloadLinks,
    downloadZipLink,
    nextButton,
    previousButton,
});
