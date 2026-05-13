import os
import threading

import torch
import argparse
import datasets
from datasets import load_dataset, load_from_disk, concatenate_datasets

datasets.disable_caching()
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import LoraConfig
from trl import DPOTrainer, DPOConfig
from transformers.trainer_utils import FSDPOption
from random import random


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--model_path", type=str, required=True)
    parser.add_argument("--dataset_path", type=str, required=True)
    parser.add_argument("--output_dir", type=str, default="./dpo_output")

    parser.add_argument("--batch_size", type=int, default=1)
    parser.add_argument("--grad_accum", type=int, default=1)

    parser.add_argument("--learning_rate", type=float, default=5e-6)
    parser.add_argument("--weight_decay", type=float, default=0.01)
    parser.add_argument("--warmup_ratio", type=float, default=0.03)
    parser.add_argument("--lr_scheduler_type", type=str, default="cosine")
    parser.add_argument("--optim", type=str, default="adamw_torch")

    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--max_steps", type=int, default=-1)
    parser.add_argument("--save_strategy", type=str, default="steps")

    parser.add_argument("--use_lora", action="store_true")
    parser.add_argument("--use_fsdp", action="store_true")

    parser.add_argument("--save_steps", type=int, default=1000)
    parser.add_argument("--save_total_limit", type=int, default=2)

    parser.add_argument("--logging_steps", type=int, default=10)
    parser.add_argument("--report_to", type=str, default="none")
    parser.add_argument("--bf16", action="store_true")

    return parser.parse_args()


tokenizer = None


def create_prompt(example):
    prompt = example['prompt']
    for i in range(len(prompt)):
        if '[BOS]' in prompt[i]['content'] or "### User:" in prompt[i]['content'] or "### Bot:" in prompt[i]['content'] or "### System:" in prompt[i]['content']:
            print(prompt[i])
        prompt[i]['content'] = prompt[i]['content'].replace("[BOS]", "").replace(" [EOS]", "").replace("### User:", "").replace("### Bot:", "").replace("### System:", "")

    if prompt[-1]['role'] != 'user':
        prompt = prompt[0:-1]
    if prompt[0]['role'] == 'system':
        prompt = prompt[1:]
    prompt = tokenizer.apply_chat_template(prompt, tokenize=False, add_generation_prompt=True)
    return {
        "prompt": prompt,
        "rejected": example['rejected'].replace(" [EOS]", ""),
        "chosen": example['chosen'].replace(" [EOS]", ""),
    }


def get_lora_config():
    return LoraConfig(
        r=8,
        lora_alpha=16,
        target_modules=["q_proj", "v_proj"],
        lora_dropout=0.1,
        bias="none",
        task_type="CAUSAL_LM",
    )


def main():
    args = parse_args()

    if args.use_fsdp:
        local_rank = int(os.environ.get("LOCAL_RANK", 0))
        print(f"Local rank: {local_rank}")
        torch.cuda.set_device(local_rank)
    else:
        local_rank = 0

    device = torch.device("cuda", local_rank) if torch.cuda.is_available() else torch.device("cpu")

    model = AutoModelForCausalLM.from_pretrained(
        args.model_path,
        torch_dtype=torch.bfloat16 if args.bf16 else torch.float16,
        low_cpu_mem_usage=True,
        attn_implementation="flash_attention_2",
        trust_remote_code=True,
    )
    global tokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.model_path, add_prefix_space=True, add_eos_token=True, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    if 'json' in args.dataset_path or 'jsonl' in args.dataset_path:
        ds = load_dataset('json', data_files=args.dataset_path, split='train')
    else:
        ds = load_from_disk(args.dataset_path)
    ds_aux = load_dataset(
        'json',
        data_files='/scratch/project_465002074/nuances/data/dpo_new_algo_parsed_hec_python_only_5k.json',
        split='train',
    ).shuffle(seed=13).select(range(0, 1500))
    ds = concatenate_datasets([ds, ds_aux])
    print(len(ds))
    ds = ds.shuffle(seed=13)
    processed_ds = ds.map(
        create_prompt,
        remove_columns=ds.column_names,
        desc="Creating 'prompt' column",
    )
    train_dataset = processed_ds.select_columns(["prompt", "chosen", "rejected"])

    training_args = DPOConfig(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        lr_scheduler_type=args.lr_scheduler_type,
        optim=args.optim,
        save_strategy=args.save_strategy,
        logging_steps=args.logging_steps,
        report_to=args.report_to,
        bf16=args.bf16,
        fp16=not args.bf16,
        loss_type='sigmoid',
        truncation_mode='keep_end',
        max_prompt_length=1200,
        beta=0.99,
        max_completion_length=1200,
        max_length=2400,
        save_safetensors=True,
        gradient_checkpointing=False,
        fsdp=[FSDPOption.FULL_SHARD, FSDPOption.AUTO_WRAP] if args.use_fsdp else None,
        fsdp_config={
            "fsdp_min_num_params": 0,
            "fsdp_transformer_layer_cls_to_wrap": ["Phi3DecoderLayer"],
            "activation_checkpointing": ["Phi3DecoderLayer"],
            "xla": False,
            "xla_fsdp_grad_ckpt": False,
        } if args.use_fsdp else None,
    )

    lora_config = get_lora_config() if args.use_lora else None

    ref_model = AutoModelForCausalLM.from_pretrained(
        args.model_path,
        torch_dtype=torch.bfloat16 if args.bf16 else torch.float16,
        trust_remote_code=True,
        attn_implementation="flash_attention_2",
    )
    ref_model.eval()
    for p in ref_model.parameters():
        p.requires_grad_(False)

    trainer = DPOTrainer(
        model=model,
        ref_model=ref_model,
        args=training_args,
        processing_class=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=None,
        peft_config=lora_config,
    )

    print("Starting training...")
    trainer.train()
    print("Training complete.")

    if torch.distributed.get_rank() == 0:
        for thread in threading.enumerate():
            if thread is not threading.main_thread():
                thread.join()


if __name__ == "__main__":
    main()
