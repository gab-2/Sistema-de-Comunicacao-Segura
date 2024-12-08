// Seletores de Elementos
const protectAESButton = document.getElementById("protect-aes-key");
const comparisonContainer = document.getElementById("comparison-container");
const processResults = document.getElementById("process-results");
const successMessage = document.getElementById("success-message");
const previousButton = document.getElementById("previous-button");
const nextButton = document.getElementById("next-button");

// Função para exibir mensagens de sucesso ou erro
const showMessage = (message, isSuccess = true) => {
    successMessage.innerHTML = `<p style="color: ${isSuccess ? "green" : "red"};">${message}</p>`;
    successMessage.style.display = "block";
};

// Função para proteger a chave AES
const protectAESKey = async () => {
    protectAESButton.disabled = true; // Desativa o botão para evitar múltiplos cliques
    comparisonContainer.style.display = "flex"; // Mostra o visual de comparação
    showMessage("Protegendo a chave AES..."); // Mensagem inicial

    try {
        console.log("Iniciando a proteção da chave AES...");

        // Faz a chamada para o backend
        const response = await fetch("/protect_aes_key", {
            method: "POST",
        });

        // Analisa a resposta do backend
        const result = await response.json();

        if (response.ok) {
            console.log("Resposta do servidor:", result);

            // Atualiza o sucesso no frontend
            comparisonContainer.style.display = "none"; // Oculta o comparativo, se necessário
            showMessage("Chave AES protegida com sucesso!", true);

            // Adiciona botão de download
            successMessage.innerHTML += `
                <a href="${result.protected_key_file}" class="btn download" download="chave_aes_protegida.pem">
                    <i class="fas fa-download"></i> Baixar Chave Protegida
                </a>
            `;
            nextButton.disabled = false; // Habilita o botão "Próximo"
        } else {
            console.error("Erro retornado pelo servidor:", result.error);
            throw new Error(result.error || "Erro ao proteger a chave AES.");
        }
    } catch (error) {
        // Mensagem de erro no frontend
        console.error("Erro no processo de proteção:", error.message);
        showMessage(`Erro: ${error.message}`, false);
    } finally {
        protectAESButton.disabled = false; // Reativa o botão após o processo
    }
};

// Botão "Proteger Chave Simétrica"
protectAESButton.addEventListener("click", protectAESKey);

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/etapa3"; // Redireciona para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa5"; // Redireciona para a próxima etapa
});
