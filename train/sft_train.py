from datasets import load_dataset
from trl import SFTTrainer, SFTConfig
from peft import LoraConfig
import torch
from transformers.trainer_utils import FSDPOption
from transformers import AutoTokenizer, AutoModelForCausalLM
import os

local_rank = os.environ.get('LOCAL_RANK')
if local_rank is not None:
    device_id = int(local_rank)
    torch.cuda.set_device(device_id)
    print(f"Rank {os.environ.get('RANK')} (Local Rank {local_rank}) set to GPU {device_id}")


def reformat_example(example):
    messages = example['messages']
    user_message = messages[0:-1]
    assistant_message = messages[-1]
    return {"prompt": user_message, "completion": [assistant_message]}


training_args = SFTConfig(
    model_init_kwargs={"torch_dtype": torch.bfloat16, "attn_implementation": 'flash_attention_2'},
    assistant_only_loss=False,
    gradient_checkpointing=False,
    max_length=2048,
    save_steps=1000,
    num_train_epochs=6,
    per_device_train_batch_size=4,
    lr_scheduler_type='linear',
    learning_rate=5e-6,
    bf16=True,
    max_grad_norm=0.9,
    warmup_steps=100,
    output_dir="/scratch/project_465002381/qwen2_5/sft3_4",
    fsdp=[FSDPOption.FULL_SHARD, FSDPOption.AUTO_WRAP],
    dataset_num_proc=112,
    completion_only_loss=True,
    gradient_accumulation_steps=4,
    weight_decay=0.1,
    fsdp_config={
        'fsdp_min_num_params': 0,
        'fsdp_transformer_layer_cls_to_wrap': ['Qwen2DecoderLayer'],
        'xla': False,
        'xla_fsdp_grad_ckpt': False,
        'fsdp_activation_checkpointing': True,
        'fsdp_offload_params': True,
    },
    gradient_checkpointing_kwargs={"use_reentrant": False},
    dataset_kwargs={
        "max_length": 2048,
        "truncation": True,
        "padding": "max_length",
        "dataset_num_proc": 112,
    },
)

ds = load_dataset(
    'json',
    data_files="/scratch/project_465002074/nuances/data/final_dataset_2026_filtered_clean2_15k_opencode.json",
)['train'].shuffle(seed=42)

reformatted_ds = ds.map(
    reformat_example,
    remove_columns=["messages"],
    num_proc=8,
)

model_pth = 'Qwen/Qwen2.5-3B-Instruct'
processing_class = AutoTokenizer.from_pretrained(model_pth, add_prefix_space=True, add_eos_token=True, trust_remote_code=True)

model = AutoModelForCausalLM.from_pretrained(
    model_pth,
    torch_dtype=torch.bfloat16,
    device_map="cpu",
    attn_implementation='flash_attention_2',
    use_cache=False,
    trust_remote_code=True,
)

trainer = SFTTrainer(
    model=model,
    train_dataset=reformatted_ds,
    args=training_args,
    processing_class=processing_class,
)

trainer.train()
