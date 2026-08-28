<script setup lang="ts">
import { computed } from 'vue'
import {
  NDynamicTags, NFormItem, NInput, NInputNumber, NSelect, NSwitch,
} from 'naive-ui'

/**
 * 由字段描述生成表单。
 *
 * 配置中心有四张表、每张十几到四十个字段,手写四份表单模板是维护灾难 ——
 * 加一个字段要改模型、序列化器、表单模板、列表列四处,而表单模板是最容易
 * 忘的那个。这里把表单收敛成一个 `fields` 数组。
 *
 * **`show` 是条件显示的钩子**:SNMP v2c 和 v3 的字段完全不同,
 * FortiGate 才有 VDOM —— 全部铺开会得到一个四十个输入框的表单,
 * 而其中三十个和当前选择无关。
 */

export interface FieldSpec {
  key: string
  label: string
  type: 'text' | 'password' | 'textarea' | 'number' | 'switch' | 'select' | 'tags' | 'json'
  /** select 的选项;传字符串则从 meta store 里按这个 key 取 */
  options?: Array<{ label: string; value: any }> | string
  placeholder?: string
  hint?: string
  min?: number
  max?: number
  step?: number
  suffix?: string
  required?: boolean
  /** 返回 false 时这个字段不显示 */
  show?: (model: Record<string, any>) => boolean
  /** 占整行(默认半行) */
  full?: boolean
  multiple?: boolean
  rows?: number
}

const props = defineProps<{
  model: Record<string, any>
  fields: FieldSpec[]
  /** 后端返回的字段级错误 { field: "消息" } */
  errors?: Record<string, string>
  optionsResolver?: (key: string) => Array<{ label: string; value: any }>
}>()

const visible = computed(() => props.fields.filter((f) => !f.show || f.show(props.model)))

function resolveOptions(field: FieldSpec) {
  if (Array.isArray(field.options)) return field.options
  if (typeof field.options === 'string' && props.optionsResolver) {
    return props.optionsResolver(field.options)
  }
  return []
}

function jsonText(value: any): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return ''
  }
}

function setJson(field: FieldSpec, text: string) {
  // 输入中途一定会经过非法 JSON 状态,所以解析失败时先存字符串,
  // 提交时由后端校验并报错 —— 边打字边弹错误框是最烦人的交互
  try {
    props.model[field.key] = text.trim() ? JSON.parse(text) : {}
  } catch {
    props.model[field.key] = text
  }
}
</script>

<template>
  <div class="sf">
    <NFormItem
      v-for="field in visible"
      :key="field.key"
      :label="field.label"
      :class="{ full: field.full || ['textarea', 'json', 'tags'].includes(field.type) }"
      :validation-status="errors?.[field.key] ? 'error' : undefined"
      :feedback="errors?.[field.key] || field.hint"
      :show-require-mark="field.required"
    >
      <NInput
        v-if="field.type === 'text'"
        v-model:value="model[field.key]" :placeholder="field.placeholder" clearable
      />
      <NInput
        v-else-if="field.type === 'password'"
        v-model:value="model[field.key]" type="password" show-password-on="click"
        :placeholder="field.placeholder"
      />
      <NInput
        v-else-if="field.type === 'textarea'"
        v-model:value="model[field.key]" type="textarea" :rows="field.rows || 3"
        :placeholder="field.placeholder"
      />
      <NInput
        v-else-if="field.type === 'json'"
        :value="jsonText(model[field.key])" type="textarea" :rows="field.rows || 4"
        :placeholder="field.placeholder"
        @update:value="(v: string) => setJson(field, v)"
      />
      <NInputNumber
        v-else-if="field.type === 'number'"
        v-model:value="model[field.key]" :min="field.min" :max="field.max" :step="field.step"
        :placeholder="field.placeholder" style="width: 100%"
      >
        <template v-if="field.suffix" #suffix>{{ field.suffix }}</template>
      </NInputNumber>
      <NSwitch v-else-if="field.type === 'switch'" v-model:value="model[field.key]" />
      <NSelect
        v-else-if="field.type === 'select'"
        v-model:value="model[field.key]" :options="resolveOptions(field)"
        :multiple="field.multiple" :placeholder="field.placeholder" clearable filterable
      />
      <NDynamicTags v-else-if="field.type === 'tags'" v-model:value="model[field.key]" />
    </NFormItem>
  </div>
</template>

<style scoped>
.sf {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 2px 16px;
}
.sf :deep(.full) { grid-column: 1 / -1; }
.sf :deep(.n-form-item-label) {
  font-size: 12px;
  color: var(--cy-ink-2);
}
.sf :deep(.n-form-item-feedback) { font-size: 10.5px; }
</style>
