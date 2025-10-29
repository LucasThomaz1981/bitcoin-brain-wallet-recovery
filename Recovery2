name: Bitcoin Brain Wallet Recovery (Parallel)

on:
  workflow_dispatch:
    inputs:
      mask_file:
        description: 'Nome do arquivo de máscaras (ex: rockyou-1-60.hcmask)'
        required: true
        default: 'rockyou-1-60.hcmask'
      addresses_file:
        description: 'Nome do arquivo de endereços (ex: addresses_with_balance.txt)'
        required: true
        default: 'addresses_with_balance.txt'
      output_file:
        description: 'Nome do arquivo de saída para chaves recuperadas'
        required: true
        default: 'recovered_keys.txt'
      num_jobs:
        description: 'Número de jobs paralelos (chunks) para dividir a execução'
        required: true
        default: 10
        type: number

jobs:
  recovery:
    runs-on: ubuntu-latest
    
    # Configura a matriz de trabalho para rodar 'num_jobs' vezes
    strategy:
      fail-fast: false
      matrix:
        # Cria uma lista de índices de 1 a 'num_jobs'
        job_index: ${{ range(1, github.event.inputs.num_jobs + 1) }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'
          
      - name: Install dependencies
        run: pip install coincurve
        
      - name: Split Mask File for Job ${{ matrix.job_index }}
        id: split_mask
        run: |
          # Executa o script de divisão para criar o arquivo de máscara específico para este job
          python3 split_masks.py ${{ github.event.inputs.mask_file }} ${{ github.event.inputs.num_jobs }} ${{ matrix.job_index }}
          echo "::set-output name=chunk_file::mask_chunk_${{ matrix.job_index }}.hcmask"
        
      - name: Run Recovery Script
        id: recovery_run
        run: |
          CHUNK_FILE=${{ steps.split_mask.outputs.chunk_file }}
          OUTPUT_FILE=recovered_keys_job_${{ matrix.job_index }}.txt
          
          # Executa o script de recuperação com o chunk de máscara
          python3 bitcoin_recovery_final.py $CHUNK_FILE ${{ github.event.inputs.addresses_file }} $OUTPUT_FILE
          
          # Verifica se o arquivo de chaves recuperadas foi criado e não está vazio
          if [ -s $OUTPUT_FILE ]; then
            echo "::set-output name=keys_found::true"
            echo "Chaves encontradas no Job ${{ matrix.job_index }}! Conteúdo do arquivo:"
            cat $OUTPUT_FILE
          else
            echo "::set-output name=keys_found::false"
            echo "Nenhuma chave encontrada nesta execução (Job ${{ matrix.job_index }})."
          fi
        
      - name: Upload Recovered Keys (if found)
        if: steps.recovery_run.outputs.keys_found == 'true'
        uses: actions/upload-artifact@v4
        with:
          name: recovered-keys-job-${{ matrix.job_index }}
          path: recovered_keys_job_${{ matrix.job_index }}.txt
          retention-days: 7
          
      - name: Notify on Failure
        if: failure()
        run: echo "::error::O job ${{ matrix.job_index }} falhou. Verifique os logs."
