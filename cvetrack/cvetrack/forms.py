from django import forms
from django.db.models import Q

from .core.tickets import TicketError, clean_number
from .models import ChangeTicket, Host


class TicketForm(forms.ModelForm):
    hosts = forms.ModelMultipleChoiceField(Host.objects.filter(active=True), required=False, label="預計主機",
                                           widget=forms.SelectMultiple(attrs={"size": 12}))

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        # 編輯時保留已退役的預計主機（不在選項裡會在儲存時被悄悄移除）
        if self.instance.pk:
            self.fields["hosts"].queryset = Host.objects.filter(Q(active=True) | Q(tickets=self.instance)).distinct()

    class Meta:
        model = ChangeTicket
        fields = ["number", "title", "description", "planned_start", "planned_end", "hosts"]
        widgets = {"planned_start": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
                   "planned_end": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
                   "description": forms.Textarea(attrs={"rows": 4})}

    def clean_number(self):
        try:
            return clean_number(self.cleaned_data["number"])
        except TicketError as e:
            raise forms.ValidationError(str(e))

    def clean(self):
        d = super().clean()
        if d.get("planned_start") and d.get("planned_end") and d["planned_end"] < d["planned_start"]:
            self.add_error("planned_end", "結束時間早於開始時間")
        return d
